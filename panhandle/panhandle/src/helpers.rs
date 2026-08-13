use aya::Btf;
use aya::programs::{KProbe, Lsm};
use aya::maps::{MapData, RingBuf};
use procfs::process::Process;
use tokio::{io::unix::AsyncFd, net::lookup_host, time::Duration};
use port_check::*;
use std::{fs::canonicalize, sync::Arc};
use url::Url;
use reqwest::{Client, Error, Response, header::CONTENT_TYPE};
use simplelog::{debug, error, info};
use syslog::{Error as SyslogError, Facility, Formatter3164};
use uzers::get_user_by_uid;
use chrono::prelude::*;

/// Reconstruct an owned, `#[repr(C)]`/`Copy` event struct from a ring buffer item. Ring buffer
/// reservations are always contiguous (unlike perf array samples), so no head/tail
/// reconstruction is needed here.
///
/// SAFETY: `T` must be exactly the plain-old-data struct written by the corresponding
/// `RingBuf::submit` call on the eBPF side, with `bytes.len() >= size_of::<T>()`.
pub(crate) unsafe fn read_ring_item<T: Copy>(bytes: &[u8]) -> T {
    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const T) }
}

// this is the local import section
use panhandle_common::*;

/// this is a method to handle the display of the shell (bash, zsh) ebpf events
pub async fn consume_shell_ebpf_map(
    client: &Client,
    mut async_fd: AsyncFd<RingBuf<MapData>>,
    ref_executable_vec: Vec<String>,
    global_url: Arc<String>,
    http: bool,
    syslog_address: Arc<String>,
    hostname: Arc<String>,
    syslog: bool,
    json: bool,
    debug: bool,
) {
    // set up vecs needed internal to the loop because of no Copy trait implementation
    let executable_vec = ref_executable_vec;

    // main cpu loop
    loop {
        let Ok(mut guard) = async_fd.readable_mut().await else {
            continue;
        };

        // drain the currently-readable items into owned copies before doing any async work,
        // since the ring buffer only hands out borrowed slices while the guard is held
        let mut events: Vec<Readline> = Vec::new();
        let ring_buf = guard.get_inner_mut();
        while let Some(item) = ring_buf.next() {
            if item.len() >= core::mem::size_of::<Readline>() {
                // SAFETY: this is implemented by a shared struct and zero'd on the ebpf side for consistency
                events.push(unsafe { read_ring_item::<Readline>(&item) });
            }
        }
        guard.clear_ready();

        for data in &events {
            // process the command to fix artifacts in the scratch
            let mut command: &str = core::str::from_utf8(&data.command)
                .unwrap_or_default()
                .trim_end_matches('\0');
            if let Some((prefix, _)) = command.split_once("\0") {
                command = prefix.trim();
            }

            // escape if matching the list of binaries to exclude
            if !executable_vec.is_empty() && !executable_vec.iter().any(|s| s == command) {
                debug!(
                    "skipping event with path: '{}' not in the list to monitor: '{:?}'",
                    command, &executable_vec
                );
                // escape iteration of events.read
                break;
            }

            // get the moniker of the uid of the event
            let user = get_user_by_uid(data.uid).unwrap();

            // timestamp
            let utc: DateTime<Utc> = Utc::now();
            let formatted_utc = utc.format("%Y-%m-%d_%H:%M:%S").to_string();

            // if json string is desired
            if json {
                let json_string = format!(
                    "{{\"application\": \"panhandle\", \"hostname\": \"{}\", \"moniker\": \"{}\", \"entry\": \"{}\", \"command\": \"{}\", \"uid\": \"{}\", \"pid\": \"{}\", \"gid\": \"{}\", \"tgid\": \"{}\", \"ts_utc\": \"{}\"}}",
                    hostname,
                    user.name().to_string_lossy(),
                    core::str::from_utf8(&data.entry)
                        .unwrap_or_default()
                        .trim_end_matches("\0")
                        .trim(),
                    core::str::from_utf8(&data.command)
                        .unwrap_or_default()
                        .trim_end_matches("\0")
                        .trim(),
                    data.uid,
                    data.pid,
                    data.gid,
                    data.tgid,
                    formatted_utc
                );
                if http {
                    let http_string = Arc::new(json_string.clone());
                    let result =
                        send_http_post(client, &global_url, &http_string, &json, &debug).await;
                    match result {
                        Ok(()) => {}
                        Err(result) => {
                            error!("HTTP POST Failed: {:?}", result);
                        }
                    }
                }

                if syslog {
                    let syslog_string = Arc::new(json_string.clone());
                    let result =
                        send_syslog(&hostname, &syslog_string, &syslog_address, &json, &debug)
                            .await;
                    match result {
                        Ok(()) => {}
                        Err(result) => {
                            error!("SYSLOG SEND Failed: {:?}", result);
                        }
                    }
                }

                if debug {
                    // this is an invalid json string, overriden by the debug
                    info!("\\{:#?}\\", json_string);
                } else {
                    // this is a valid json string
                    info!("{}", json_string);
                }
            } else {
                let string = format!(
                    "application: panhandle, hostname: {}, moniker: {}, {}, ts_utc: '{}'",
                    hostname,
                    user.name().to_string_lossy(),
                    data,
                    formatted_utc
                );
                if http {
                    let http_string = Arc::new(string.clone());
                    let result =
                        send_http_post(client, &global_url, &http_string, &json, &debug).await;
                    match result {
                        Ok(()) => {}
                        Err(result) => {
                            error!("HTTP POST Failed: {:?}", result);
                        }
                    }
                }
                if syslog {
                    let syslog_string = Arc::new(string.clone());
                    let result =
                        send_syslog(&hostname, &syslog_string, &syslog_address, &json, &debug)
                            .await;
                    match result {
                        Ok(()) => {}
                        Err(result) => {
                            error!("SYSLOG SEND Failed: {:?}", result);
                        }
                    }
                }
                // this is the human readable output
                info!("{}", string);
            }
        }
    }
}

/// this is a method to handle the display of the execve ebpf events
pub async fn consume_execve_ebpf_map(
    client: &Client,
    mut async_fd: AsyncFd<RingBuf<MapData>>,
    ref_executable_vec: Vec<String>,
    global_url: Arc<String>,
    http: bool,
    syslog_address: Arc<String>,
    hostname: Arc<String>,
    syslog: bool,
    json: bool,
    debug: bool,
) {
    // set up vecs needed internal to the loop because of no Copy trait implementation
    let executable_vec = ref_executable_vec;

    // main cpu loop
    loop {
        let Ok(mut guard) = async_fd.readable_mut().await else {
            continue;
        };

        // drain the currently-readable items into owned copies before doing any async work,
        // since the ring buffer only hands out borrowed slices while the guard is held
        let mut events: Vec<ExecveEvent> = Vec::new();
        let ring_buf = guard.get_inner_mut();
        while let Some(item) = ring_buf.next() {
            if item.len() >= core::mem::size_of::<ExecveEvent>() {
                // SAFETY: this is implemented by a shared struct and zero'd on the ebpf side for consistency
                events.push(unsafe { read_ring_item::<ExecveEvent>(&item) });
            }
        }
        guard.clear_ready();

        for data in &events {
            // process the command to fix artifacts in the scratch
            let mut command = core::str::from_utf8(&data.command)
                .unwrap_or_default()
                .trim_end_matches('\0');
            if let Some((prefix, _)) = command.split_once("\0") {
                command = prefix.trim();
            }

            // parse the filename and clean up any existence of artifacts
            let mut filename = core::str::from_utf8(&data.filename)
                .unwrap_or_default()
                .trim_end_matches('\0');
            if let Some((prefix, _)) = filename.split_once("\0") {
                filename = prefix.trim();
            }

            // escape if matching the list of binaries to exclude
            if !executable_vec.is_empty() && !executable_vec.iter().any(|s| s == filename) {
                debug!(
                    "skipping event with path: '{}' not in the list to monitor: '{:?}'",
                    filename, &executable_vec
                );
                // escape iteration of events.read
                break;
            }

            // get the moniker of the uid of the event
            let user: uzers::User = get_user_by_uid(data.uid).unwrap();

            // timestamp
            let utc: DateTime<Utc> = Utc::now();
            let formatted_utc = utc.format("%Y-%m-%d_%H:%M:%S").to_string();

            // log this event, the main thing!
            if json {
                let mut envvec: Vec<&str> = Vec::new();
                for env_ptr in &data.envp {
                    let mut env: &str = core::str::from_utf8(env_ptr).unwrap_or_default().trim();
                    if !env.starts_with('\u{0}') {
                        if let Some((prefix, _)) = env.split_once("\0") {
                            env = prefix;
                        }
                        envvec.push(env.trim_end_matches('\0'));
                    }
                }
                let mut argvec: Vec<&str> = Vec::new();
                for arg_ptr in &data.argv {
                    let mut arg: &str = core::str::from_utf8(arg_ptr).unwrap_or_default().trim();
                    if !arg.starts_with('\u{0}') {
                        if let Some((prefix, _)) = arg.split_once("\0") {
                            arg = prefix;
                        }
                        argvec.push(arg.trim_end_matches('\0'));
                    }
                }
                let json_string: String = format!(
                    "{{\"application\": \"panhandle\", \"hostname\": \"{}\", \"moniker\": \"{}\", \"filename\": \"{}\", \"command\": \"{}\", \"uid\": \"{}\", \"pid\": \"{}\", \"gid\": \"{}\", \"tgid\": \"{}\", \"args\": {:?}, \"envs\": {:?}, \"ts_utc\": {:?} }}",
                    hostname,
                    user.name().to_string_lossy(),
                    filename,
                    command,
                    data.uid,
                    data.pid,
                    data.gid,
                    data.tgid,
                    argvec,
                    envvec,
                    formatted_utc
                );
                if http {
                    let http_string: Arc<String> = Arc::new(json_string.clone());
                    let result: Result<(), Error> =
                        send_http_post(client, &global_url.clone(), &http_string, &json, &debug)
                            .await;
                    match result {
                        Ok(()) => {}
                        Err(result) => {
                            error!("HTTP POST Failed: {:?}", result);
                        }
                    }
                } 
                if syslog {
                    let syslog_string: Arc<String> = Arc::new(json_string.clone());
                    let result: Result<(), SyslogError> =
                        send_syslog(&hostname, &syslog_string, &syslog_address, &json, &debug)
                            .await;
                    match result {
                        Ok(()) => {}
                        Err(result) => {
                            error!("SYSLOG SEND Failed: {:?}", result);
                        }
                    }
                }
                if debug {
                    info!("\\{:#?}\\", json_string);
                } else {
                    info!("{}", json_string);
                }
            } else {
                let string = format!(
                    "application: panhandle, hostname: {}, moniker: {}, {}, ts_utc: '{}'",
                    hostname,
                    user.name().to_string_lossy(),
                    data,
                    formatted_utc
                );
                if http {
                    let http_string: Arc<String> = Arc::new(string.clone());
                    let result: Result<(), Error> =
                        send_http_post(client, &global_url, &http_string, &json, &debug).await;
                    match result {
                        Ok(()) => {}
                        Err(result) => {
                            error!("HTTP POST Failed: {:?}", result);
                        }
                    }
                } 
                if syslog {
                    let syslog_string: Arc<String> = Arc::new(string.clone());
                    let result: Result<(), SyslogError> =
                        send_syslog(&hostname, &syslog_string, &syslog_address, &json, &debug)
                            .await;
                    match result {
                        Ok(()) => {}
                        Err(result) => {
                            error!("SYSLOG SEND Failed: {:?}", result);
                        }
                    }
                } 
                // this is the human readable output
                info!("{}", string);
            }
        }
    }
}

/// send to specified syslog address.
pub async fn send_syslog(
    hostname: &String, // hostname
    arc_string: &Arc<String>,
    syslog_address: &Arc<String>,
    json: &bool,  // free-form message bool for json vs. text
    debug: &bool, // help with debugging
) -> Result<(), SyslogError> {
    // set formatter for syslog message
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: Some(hostname.to_string()),
        process: "panhandle".into(),
        pid: std::process::id(),
    };

    // slice off /udp or /tcp to get the address
    let host_and_port = syslog_address
        .trim_end_matches("/tcp")
        .trim_end_matches("/udp");

    // create writer for either tcp, udp, or local
    let mut writer = if syslog_address.ends_with("/tcp") {
        match syslog::tcp(formatter, host_and_port.to_string()) {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to connect to TCP syslog server: {:?}", e);
                return Err(e);
            }
        }
    } else if syslog_address.ends_with("/udp") {
        match syslog::udp(formatter, "0.0.0.0:0", host_and_port.to_string()) {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to connect to UDP syslog server: {:?}", e);
                return Err(e);
            }
        }
    } else {
        match syslog::unix(formatter) {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to connect to local syslog: {:?}", e);
                return Err(e);
            }
        }
    };

    // Convert Arc<String> to normal String for logging
    let message = arc_string.to_string();

    if *json {
        match serde_json::from_str::<serde_json::Value>(&message) {
            Ok(val) => {
                let mut free_form_message = val.to_string();
                // Add newline for TCP framing
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
                        return Err(e);
                    }
                }
            }
            Err(e) => {
                error!("Invalid JSON: {:?}", e);
            }
        }
    } else {
        let mut plaintext_message = message.replace('\0', ""); // remove all \0 characters in message
        // Add newline for TCP framing
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
                return Err(e);
            }
        }
    }

    Ok(())
}

/// send a http post to a specified http url
pub async fn send_http_post(
    client: &Client,
    url: &Arc<String>,
    arc_string: &Arc<String>,
    json: &bool,
    debug: &bool,
) -> Result<(), Error> {
    let mut content_type: &str = "text/plain";

    if *json {
        //send json post
        let to_json_message: String = arc_string.to_string();
        content_type = "application/json";
        match serde_json::from_str::<serde_json::Value>(to_json_message.as_str()) {
            Ok(val) => {
                let message = val.to_string();
                let _response: Response = client
                    .post(url.to_string().as_str())
                    .timeout(Duration::from_millis(200))
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
        // send text post
        let message: String = arc_string.to_string();
        let response: Response = client
            .post(url.to_string().as_str())
            .timeout(Duration::from_millis(200))
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

/// return a modified vec of the args provided plus the canonical paths if those exist
pub fn get_canonical_executable_list(arg_vec: &Vec<String>) -> Vec<String> {
    let mut return_vec: Vec<String> = Vec::new();
    // canonicalize the paths so /bin includes /usr/bin etc
    for path in arg_vec {
        // first do what the user asked for
        return_vec.push(path.clone());
        // then try to add a canonical path if it exists
        let pathbuf = canonicalize(path.as_str()).unwrap_or_default();
        // we can only monitor files or symlinks
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
pub async fn validate_syslog(addr: &str) -> Result<&str, String> {
    if addr == "unix" || addr == "/dev/log" || addr.is_empty() {
        Ok(addr) // valid
    } else if addr.ends_with("/tcp") || addr.ends_with("/udp") {
        // validate the remote server address provided
        let host_and_port = addr.trim_end_matches("/tcp").trim_end_matches("/udp");

        // DNS resolution of the provided hostname
        if lookup_host(host_and_port).await.is_err() {
            Err("\nSYSLOG: Invalid remote address hostname provided. \
                        \nBe sure to enter in the format: --syslog <hostname>:<port>/tcp or /udp"
                .to_string())
        }
        // check if the TCP port is reachable and return error after 3 seconds if not
        else if !(is_port_reachable_with_timeout(host_and_port, Duration::from_secs(3)))
            && addr.ends_with("/tcp")
        {
            Err("\nSYSLOG: Provided TCP port number is not reachable. \
                        \nBe sure to enter in the format: --syslog <hostname>:<port>/tcp or /udp"
                .to_string())
        } else {
            Ok(addr) // valid host and tcp/udp extension given
        }
    } else {
        Err(format!(
            "\nSYSLOG: Invalid syslog argument '{}' provided. \
            \nUSAGE:\n  Local syslog message output: --syslog /dev/log or --syslog unix or --syslog \
            \n  Remote syslog message output: --syslog <hostname>:<port>/tcp or /udp",
            addr
        ))
    }
}

/// Determine which comm allow/deny list mode is active from the CLI args, and which comm
/// list to populate the eBPF map with. Returns an error if both --comm-deny and
/// --comm-allow were provided, since only one list mode can be active at a time.
pub fn resolve_comm_list_mode(
    comm_deny: &Option<Vec<String>>,
    comm_allow: &Option<Vec<String>>,
) -> Result<(u8, Vec<String>), String> {
    match (comm_deny, comm_allow) {
        (Some(_), Some(_)) => {
            Err("Allow and deny list both provided, exiting with error.".to_string())
        }
        (Some(deny), None) => Ok((DENY_LIST, deny.clone())),
        (None, Some(allow)) => Ok((ALLOW_LIST, allow.clone())),
        (None, None) => Ok((NO_LIST, Vec::new())),
    }
}

/// Error if more than `max` of something (identified by `label` in the message, e.g.
/// "executables" or "UIDs") were requested to monitor.
pub fn validate_count(len: usize, max: usize, label: &str) -> Result<(), String> {
    if len > max {
        Err(format!(
            "The number of {} requested to monitor exceeds the maximum of {}",
            label, max
        ))
    } else {
        Ok(())
    }
}

pub async fn validate_url(url: &str) -> Result<&str, String> {
    // validate given URL
    if Url::parse(url).is_err() {
        Err(format!("\nInvalid URL '{}' provided", url))
    } else {
        Ok(url) // URL found valid
    }
}

/// Whether the plain-text and/or JSON form of a message is actually needed, given the
/// configured output channels. Mirrors `output_message`'s own selection logic below:
/// `plain_string` is used for non-JSON output; `json_string` is used when `--json` is
/// requested or `--debug` is set (debug always logs the JSON form). Because `--json`
/// is a global flag, every active channel -- http/syslog transport and the terminal
/// alike -- uses the same form, so the JSON form is needed whenever it is requested.
/// The only wrinkle is a non-JSON transport combined with `--debug`, which still sends
/// the plain form over the wire while the terminal logs the JSON form. Computing this
/// once per report call lets callers skip building whichever string won't be used.
pub fn output_needs(http: bool, syslog: bool, json_output: bool, debug: bool) -> (bool, bool) {
    let needs_plain = !json_output && (!debug || http || syslog);
    let needs_json = json_output || debug;
    (needs_plain, needs_json)
}

/// Render a process owner for --verbose output. The UID renders as "unknown" rather than
/// a numeric fallback like 0 when it couldn't be resolved -- 0 is root's real UID, so
/// defaulting to it would misattribute an unresolved process's ownership to root.
pub fn format_owner(uid: Option<u32>, username: Option<&str>) -> (String, String) {
    let uid_str = uid
        .map(|u| u.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let username_str = username.unwrap_or("unknown").to_string();
    (uid_str, username_str)
}

/// Render a process state char for --verbose output, an empty string when unavailable
/// (e.g. the --gpu monitor, which has no Stat read to source a state from).
pub fn format_state(state: Option<char>) -> String {
    state.map(|s| s.to_string()).unwrap_or_default()
}

/// Human-readable name for a /proc process state char, for the --verbose plain-text
/// output. The JSON form keeps the raw state char via `format_state`.
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

/// Delta since the last observed value. Returns 0 when there's no prior observation yet,
/// rather than treating "never observed" the same as "observed as 0" (which would compute
/// a delta spanning the process/system's entire lifetime and report it as if it all
/// happened within a single poll interval -- a misleading spike on the very first sample
/// after monitoring starts).
pub fn calc_delta(current: u64, last: Option<u64>) -> u64 {
    match last {
        Some(last) => current.saturating_sub(last),
        None => 0,
    }
}

/// wrapper method to handle output formatting to syslog or http
pub async fn output_message(
    http: &bool, 
    syslog: &bool, 
    hostname: &Arc<String>,
    syslog_address: &Arc<String>,
    global_url: &Arc<String>,
    use_json: &bool, 
    plain_string: &String, 
    json_string: &String, 
    client: &Client, 
    debug: &bool
) {
    if *http {
        if *use_json {
            let arc_string = Arc::new(json_string.clone().to_string());
            let result =
                send_http_post(client, global_url, &arc_string, use_json, debug).await;
            match result {
                Ok(()) => {}
                Err(result) => {
                    error!("HTTP POST Failed: {:?}", result);
                }
            }
        } else {
            let arc_string = Arc::new(plain_string.clone().to_string());
            let result =
                send_http_post(client, global_url, &arc_string, use_json, debug).await;
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
            let result =
                send_syslog(hostname, &arc_string, syslog_address, use_json, debug)
                    .await;
            match result {
                Ok(()) => {}
                Err(result) => {
                    error!("SYSLOG SEND Failed: {:?}", result);
                }
            }
        } else {
            let arc_string = Arc::new(plain_string.clone().to_string());
            let result =
                send_syslog(hostname, &arc_string, syslog_address, use_json, debug)
                    .await;
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

/// Helper function to attach a single kprobe
pub fn attach_kprobe(ebpf: &mut aya::Ebpf, program_name: &str) -> Result<(), anyhow::Error> {
    let program: &mut KProbe = ebpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow::anyhow!("Program '{}' not found", program_name))?
        .try_into()
        .inspect_err(|e| error!("failed to load eBPF program '{}': {}", program_name, e))?;

    program
        .load()
        .inspect_err(|e| error!("failed to load kprobe '{}': {}", program_name, e))?;
    program
        .attach(program_name, 0)
        .inspect_err(|e| error!("failed to attach kprobe '{}': {}", program_name, e))?;

    debug!("attached eBPF kprobe '{}'", program_name);
    Ok(())
}

/// Helper function to attach a single LSM hook
pub fn attach_lsm_hook(
    ebpf: &mut aya::Ebpf,
    hook_name: &str,
    program_name: &str,
) -> Result<(), anyhow::Error> {
    let program: &mut Lsm = ebpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow::anyhow!("Program '{}' not found", program_name))?
        .try_into()
        .inspect_err(|e| error!("failed to load eBPF program '{}': {}", program_name, e))?;
    let btf = Btf::from_sys_fs()
        .inspect_err(|e| error!("failed to read BTF from sysfs for '{}': {}", hook_name, e))?;
    program
        .load(hook_name, &btf)
        .inspect_err(|e| error!("failed to load LSM hook '{}' ({}): {}", hook_name, program_name, e))?;
    program
        .attach()
        .inspect_err(|e| error!("failed to attach LSM hook '{}' ({}): {}", hook_name, program_name, e))?;

    debug!(
        "attached eBPF LSM hook '{}' (program '{}')",
        hook_name, program_name
    );
    Ok(())
}

/// Get process name from PID
pub fn get_process_name(pid: u32) -> Option<String> {
    Process::new(pid as i32)
        .ok()
        .and_then(|proc| proc.stat().ok())
        .map(|stat| stat.comm)
}

/// Get the parent PID for a given PID
pub fn get_parent_pid(pid: u32) -> Result<u32, Box<dyn std::error::Error>> {
    let proc = Process::new(pid as i32)?;
    let stat = proc.stat()?;
    Ok(stat.ppid as u32)
}

/// Get the real UID that owns a process, from /proc/<pid>/status.
pub fn get_process_uid(pid: u32) -> Option<u32> {
    Some(Process::new(pid as i32).ok()?.status().ok()?.ruid)
}

/// Resolve a UID to its username, falling back to "unknown" rather than failing outright
/// when the UID doesn't map to a known user (e.g. an NSS/LDAP lookup failure) -- the UID
/// itself is still meaningful even when the name isn't available. This can hit
/// network-backed NSS, so callers polling many processes in --verbose mode should cache
/// the result per UID for the duration of a single poll (most processes on a host share a
/// handful of UIDs), the same way parent-comm lookups are already cached.
pub fn resolve_username(uid: u32) -> String {
    get_user_by_uid(uid)
        .map(|u| u.name().to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string())
}