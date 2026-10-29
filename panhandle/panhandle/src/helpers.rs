use crate::error::{PanhandleError, Result};
use panhandle_common::*;
use port_check::*;
use procfs::process::Process;
use reqwest::{Client, Response, header::CONTENT_TYPE};
use simplelog::{debug, error, info};
use std::{fs::canonicalize, sync::Arc};
use syslog::{Facility, Formatter3164};
use tokio::{net::lookup_host, time::Duration};
use url::Url;
use uzers::get_user_by_uid;

/// Reconstruct an owned, `#[repr(C)]`/`Copy` event struct from a ring buffer item. Ring buffer
/// reservations are always contiguous (unlike perf array samples), so no head/tail
/// reconstruction is needed here.
///
/// # Safety
///
/// `T` must be exactly the plain-old-data struct written by the corresponding
/// `RingBuf::submit` call on the eBPF side, with `bytes.len() >= size_of::<T>()`.
pub unsafe fn read_ring_item<T: Copy>(bytes: &[u8]) -> T {
    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const T) }
}

/// Whether an event should be reported, given the `--executables` filter. An empty filter
/// means "monitor everything", so every event matches.
///
/// Callers must skip a non-matching event individually (`continue`), never abandon the rest
/// of the batch (`break`): a single readable drain of the ring buffer yields many unrelated
/// events, so one non-match says nothing about the events queued behind it.
pub fn event_matches_executable_filter(filter: &[String], candidate: &str) -> bool {
    filter.is_empty() || filter.iter().any(|s| s == candidate)
}

/// Return a modified vec of the args provided plus the canonical paths if those exist
pub fn get_canonical_executable_list(arg_vec: &Vec<String>) -> Vec<String> {
    let mut return_vec: Vec<String> = Vec::new();
    for path in arg_vec {
        return_vec.push(path.clone());
        let pathbuf = canonicalize(path.as_str()).unwrap_or_default();
        if pathbuf.is_file() || pathbuf.is_symlink() {
            let pathstring = pathbuf.display().to_string();
            debug!("canonicalized {} to {:#?}", path.as_str(), pathstring);
            if !return_vec.contains(&pathstring) {
                return_vec.push(pathstring);
            }
        }
    }
    debug!("canonicalized list of paths is {:?}", return_vec);
    return_vec
}

/// validates the host name and port number given to the syslog argument
pub async fn validate_syslog(addr: &str) -> Result<&str> {
    if addr == "unix" || addr == "/dev/log" || addr.is_empty() {
        Ok(addr)
    } else if addr.ends_with("/tcp") || addr.ends_with("/udp") {
        let host_and_port = addr.trim_end_matches("/tcp").trim_end_matches("/udp");
        if lookup_host(host_and_port).await.is_err() {
            Err(PanhandleError::Config(
                "\nSYSLOG: Invalid remote address hostname provided. \
                \nBe sure to enter in the format: --syslog <hostname>:<port>/tcp or /udp"
                    .to_string(),
            ))
        } else if !(is_port_reachable_with_timeout(host_and_port, Duration::from_secs(3)))
            && addr.ends_with("/tcp")
        {
            Err(PanhandleError::Config(
                "\nSYSLOG: Provided TCP port number is not reachable. \
                \nBe sure to enter in the format: --syslog <hostname>:<port>/tcp or /udp"
                    .to_string(),
            ))
        } else {
            Ok(addr)
        }
    } else {
        Err(PanhandleError::Config(format!(
            "\nSYSLOG: Invalid syslog argument '{}' provided. \
            \nUSAGE:\n  Local syslog message output: --syslog /dev/log or --syslog unix or --syslog \
            \n  Remote syslog message output: --syslog <hostname>:<port>/tcp or /udp",
            addr
        )))
    }
}

/// Error if more than `max` of something (identified by `label` in the message, e.g.
/// "executables" or "UIDs") were requested to monitor.
pub fn validate_count(len: usize, max: usize, label: &str) -> Result<()> {
    if len > max {
        Err(PanhandleError::Config(format!(
            "The number of {} requested to monitor exceeds the maximum of {}",
            label, max
        )))
    } else {
        Ok(())
    }
}

pub async fn validate_url(url: &str) -> Result<&str> {
    if Url::parse(url).is_err() {
        Err(PanhandleError::Config(format!(
            "\nInvalid URL '{}' provided",
            url
        )))
    } else {
        Ok(url)
    }
}

/// Determine which comm allow/deny list mode is active from the CLI args, and which comm
/// list to populate the eBPF map with. Returns an error if both --comm-deny and
/// --comm-allow were provided, since only one list mode can be active at a time.
#[allow(dead_code)]
pub fn resolve_comm_list_mode(
    comm_deny: &Option<Vec<String>>,
    comm_allow: &Option<Vec<String>>,
) -> Result<(u8, Vec<String>)> {
    match (comm_deny, comm_allow) {
        (Some(_), Some(_)) => Err(PanhandleError::Config(
            "Allow and deny list both provided, exiting with error.".to_string(),
        )),
        (Some(deny), None) => Ok((DENY_LIST, deny.clone())),
        (None, Some(allow)) => Ok((ALLOW_LIST, allow.clone())),
        (None, None) => Ok((NO_LIST, Vec::new())),
    }
}

/// JSON-escape a string field so it can be interpolated into a hand-built JSON object
/// template without breaking the document when the value contains quotes, backslashes,
/// or control characters. Serializing a `&str` cannot fail, so the expect is unreachable.
#[allow(dead_code)]
pub fn json_quoted(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a &str cannot fail")
}

/// Render a process owner for --verbose output. The UID renders as "unknown" rather than
/// a numeric fallback like 0 when it couldn't be resolved -- 0 is root's real UID, so
/// defaulting to it would misattribute an unresolved process's ownership to root.
#[allow(dead_code)]
pub fn format_owner(uid: Option<u32>, username: Option<&str>) -> (String, String) {
    let uid_str = uid
        .map(|u| u.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let username_str = username.unwrap_or("unknown").to_string();
    (uid_str, username_str)
}

/// Render a process state char for --verbose output, an empty string when unavailable
#[allow(dead_code)]
pub fn format_state(state: Option<char>) -> String {
    state.map(|s| s.to_string()).unwrap_or_default()
}

/// Human-readable name for a /proc process state char, for the --verbose plain-text output.
#[allow(dead_code)]
pub fn format_state_prose(state: Option<char>) -> String {
    let word = match state {
        Some('R') => "running",
        Some('S') => "sleeping",
        Some('D') => "disk sleep",
        Some('Z') => "zombie",
        Some('T') => "stopped",
        Some('t') => "tracing stop",
        Some('X') => "dead",
        Some('I') => "idle",
        Some('P') => "parked",
        _ => "unknown",
    };
    word.to_string()
}

/// Delta since the last observed value. Returns 0 when there's no prior observation yet.
#[allow(dead_code)]
pub fn calc_delta(current: u64, last: Option<u64>) -> u64 {
    match last {
        Some(last) => current.saturating_sub(last),
        None => 0,
    }
}

/// Get process name from PID
#[allow(dead_code)]
pub fn get_process_name(pid: u32) -> Option<String> {
    Process::new(pid as i32)
        .ok()
        .and_then(|proc| proc.stat().ok())
        .map(|stat| stat.comm)
}

/// Get the parent PID for a given PID
#[allow(dead_code)]
pub fn get_parent_pid(pid: u32) -> Result<u32> {
    let proc = Process::new(pid as i32).map_err(PanhandleError::Procfs)?;
    let stat = proc.stat().map_err(PanhandleError::Procfs)?;
    Ok(stat.ppid as u32)
}

/// Get the real UID that owns a process, from /proc/<pid>/status.
#[allow(dead_code)]
pub fn get_process_uid(pid: u32) -> Option<u32> {
    Some(Process::new(pid as i32).ok()?.status().ok()?.ruid)
}

/// Resolve a UID to its username, falling back to "unknown"
#[allow(dead_code)]
pub fn resolve_username(uid: u32) -> String {
    get_user_by_uid(uid)
        .map(|u| u.name().to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Determine which output formats are needed based on CLI flags.
/// Returns (needs_plain, needs_json).
#[allow(dead_code)]
pub fn output_needs(http: bool, syslog: bool, json_output: bool, debug: bool) -> (bool, bool) {
    let needs_plain = !json_output && (!debug || http || syslog);
    let needs_json = json_output || debug;
    (needs_plain, needs_json)
}

/// Send output to configured channels (console, HTTP, syslog).
#[allow(dead_code)]
pub async fn output_message(
    http: &bool,
    syslog: &bool,
    hostname: &Arc<String>,
    syslog_address: &Arc<String>,
    http_url: &Arc<String>,
    use_json: &bool,
    plain_string: &String,
    json_string: &String,
    client: &Client,
    debug: &bool,
) {
    if *http {
        if *use_json {
            let arc_string = Arc::new(json_string.clone().to_string());
            let result = send_http_post(client, http_url, &arc_string, use_json, debug).await;
            match result {
                Ok(()) => {}
                Err(result) => {
                    error!("HTTP POST Failed: {:?}", result);
                }
            }
        } else {
            let arc_string = Arc::new(plain_string.clone().to_string());
            let result = send_http_post(client, http_url, &arc_string, use_json, debug).await;
            match result {
                Ok(()) => {}
                Err(result) => {
                    error!("HTTP POST Failed: {:?}", result);
                }
            }
        }
    }
    if *syslog {
        if *use_json {
            let arc_string = Arc::new(json_string.clone().to_string());
            let result = send_syslog(hostname, &arc_string, syslog_address, use_json, debug).await;
            match result {
                Ok(()) => {}
                Err(result) => {
                    error!("SYSLOG SEND Failed: {:?}", result);
                }
            }
        } else {
            let arc_string = Arc::new(plain_string.clone().to_string());
            let result = send_syslog(hostname, &arc_string, syslog_address, use_json, debug).await;
            match result {
                Ok(()) => {}
                Err(result) => {
                    error!("SYSLOG SEND Failed: {:?}", result);
                }
            }
        }
    }
    if *debug {
        info!("\\{:#?}\\", json_string);
    } else if *use_json {
        info!("{}", json_string);
    } else {
        info!("{}", plain_string);
    }
}

/// send a http post to a specified http url
#[allow(dead_code)]
pub async fn send_http_post(
    client: &Client,
    url: &Arc<String>,
    arc_string: &Arc<String>,
    json: &bool,
    debug: &bool,
) -> Result<()> {
    let mut content_type: &str = "text/plain";

    if *json {
        let to_json_message: String = arc_string.to_string();
        content_type = "application/json";
        match serde_json::from_str::<serde_json::Value>(to_json_message.as_str()) {
            Ok(val) => {
                let message = val.to_string();
                let _response: Response = client
                    .post(url.to_string().as_str())
                    .timeout(Duration::from_secs(3))
                    .header(CONTENT_TYPE, content_type)
                    .body(message)
                    .send()
                    .await?;
            }
            Err(val) => {
                error!("{:?}", val);
            }
        }
    } else {
        let message: String = arc_string.to_string();
        let response: Response = client
            .post(url.to_string().as_str())
            .timeout(Duration::from_secs(3))
            .header(CONTENT_TYPE, content_type)
            .body(message)
            .send()
            .await?;
        if *debug {
            info!(
                "Completed https request with response code: {:#?}",
                response.status()
            );
        }
        match response.status() {
            reqwest::StatusCode::OK => {}
            reqwest::StatusCode::UNAUTHORIZED => {
                info!("Unauthorized!");
            }
            reqwest::StatusCode::REQUEST_TIMEOUT => {
                error!("Connection timed out");
            }
            _ => {
                error!("Unexpected error sending HTTP POST!");
            }
        }
    };
    Ok(())
}

/// send to specified syslog address.
#[allow(dead_code)]
pub async fn send_syslog(
    hostname: &String,
    arc_string: &Arc<String>,
    syslog_address: &Arc<String>,
    json: &bool,
    debug: &bool,
) -> Result<()> {
    tokio::task::block_in_place(|| {
        send_syslog_blocking(hostname, arc_string, syslog_address, json, debug)
    })
}

#[allow(dead_code)]
fn send_syslog_blocking(
    hostname: &String,
    arc_string: &Arc<String>,
    syslog_address: &Arc<String>,
    json: &bool,
    debug: &bool,
) -> Result<()> {
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: Some(hostname.to_string()),
        process: "panhandle".into(),
        pid: std::process::id(),
    };

    let host_and_port = syslog_address
        .trim_end_matches("/tcp")
        .trim_end_matches("/udp");

    let mut writer = if syslog_address.ends_with("/tcp") {
        match syslog::tcp(formatter, host_and_port.to_string()) {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to connect to TCP syslog server: {:?}", e);
                return Err(PanhandleError::Syslog(e));
            }
        }
    } else if syslog_address.ends_with("/udp") {
        match syslog::udp(formatter, "0.0.0.0:0", host_and_port.to_string()) {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to connect to UDP syslog server: {:?}", e);
                return Err(PanhandleError::Syslog(e));
            }
        }
    } else {
        match syslog::unix(formatter) {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to connect to local syslog: {:?}", e);
                return Err(PanhandleError::Syslog(e));
            }
        }
    };

    let message = arc_string.to_string();

    if *json {
        match serde_json::from_str::<serde_json::Value>(&message) {
            Ok(val) => {
                let mut free_form_message = val.to_string();
                if syslog_address.ends_with("/tcp") {
                    free_form_message.push('\n');
                }
                match writer.info(free_form_message.as_str()) {
                    Ok(_) => {
                        if *debug {
                            info!("[DEBUG] JSON message sent to syslog");
                        }
                    }
                    Err(e) => {
                        error!("Error sending JSON to syslog: {:?}", e);
                        return Err(PanhandleError::Syslog(e));
                    }
                }
            }
            Err(e) => {
                error!("Invalid JSON: {:?}", e);
            }
        }
    } else {
        let mut plaintext_message = message.replace('\0', "");
        if syslog_address.ends_with("/tcp") {
            plaintext_message.push('\n');
        }
        match writer.info(plaintext_message.as_str()) {
            Ok(_) => {
                if *debug {
                    info!("[DEBUG] Plaintext message sent to syslog");
                }
            }
            Err(e) => {
                error!("Error sending plaintext to syslog: {:?}", e);
                return Err(PanhandleError::Syslog(e));
            }
        }
    }
    Ok(())
}
