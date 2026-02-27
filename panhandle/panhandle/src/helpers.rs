use aya::maps::perf::AsyncPerfEventArrayBuffer;
use tokio::{net::lookup_host, time::Duration};
extern crate simplelog;
use port_check::*;
use std::{fs::canonicalize, sync::Arc};
use url::Url;
use reqwest::{Client, Error, Response, header::CONTENT_TYPE};
use simplelog::{info, debug};
use syslog::{Error as SyslogError, Facility, Formatter3164};
use uzers::get_user_by_uid;
use bytes::BytesMut;
use chrono::prelude::*;
// this is the local import section
use panhandle_common::*;

/// this is a method to handle the display of the shell (bash, zsh) ebpf events
pub async fn consume_shell_ebpf_map(
    client: &Client,
    mut buf: AsyncPerfEventArrayBuffer<aya::maps::MapData>,
    mut buffers: Vec<BytesMut>,
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
        let events: aya::maps::perf::Events = buf.read_events(&mut buffers).await.unwrap();
        for buf in buffers.iter_mut().take(events.read) {
            // read the event
            let ptr: *const Readline = buf.as_ptr() as *const Readline;
            // SAFETY: derefernce the pointer that we created in ebpf-land
            // this is implemented by a shared struct and zero'd on the ebpf side for consistency
            let data: &Readline = unsafe { &*ptr };

            // process the command to fix artifacts in the scratch
            let mut command: &str = core::str::from_utf8(&data.command)
                .unwrap_or_default()
                .trim_end_matches('\0');
            if let Some((prefix, _)) = command.split_once("\0") {
                command = prefix.trim();
            }

            // escape if matching the list of binaries to exclude
            if !executable_vec.is_empty() && !executable_vec.contains(&command.to_string()) {
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
                    &hostname,
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
                            info!("HTTP POST Failed: {:?}", result);
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
                            debug!("SYSLOG SEND Failed: {:?}", result);
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
                    &hostname,
                    user.name().to_string_lossy(),
                    data,
                    formatted_utc
                );
                if http {
                    let http_string = Arc::new(string);
                    let result =
                        send_http_post(client, &global_url, &http_string, &json, &debug).await;
                    match result {
                        Ok(()) => {}
                        Err(result) => {
                            info!("HTTP POST Failed: {:?}", result);
                        }
                    }
                } else if syslog {
                    let syslog_string = Arc::new(string);
                    let result =
                        send_syslog(&hostname, &syslog_string, &syslog_address, &json, &debug)
                            .await;
                    match result {
                        Ok(()) => {}
                        Err(result) => {
                            debug!("SYSLOG SEND Failed: {:?}", result);
                        }
                    }
                } else {
                    // this is the human readable output
                    info!("{}", string);
                }
            }
        }
    }
}

/// this is a method to handle the display of the execve ebpf events
pub async fn consume_execve_ebpf_map(
    client: &Client,
    mut buf: AsyncPerfEventArrayBuffer<aya::maps::MapData>,
    mut buffers: Vec<BytesMut>,
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
        let events: aya::maps::perf::Events = buf.read_events(&mut buffers).await.unwrap();
        for buf in buffers.iter_mut().take(events.read) {
            // read the event
            let ptr: *const ExecveEvent = buf.as_ptr() as *const ExecveEvent;
            // SAFETY: derefernce the pointer that we created in ebpf-land
            // this is implemented by a shared struct and zero'd on the ebpf side for consistency
            let data: &ExecveEvent = unsafe { &*ptr };

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
            if !executable_vec.is_empty() && !executable_vec.contains(&filename.to_string()) {
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
                    &hostname,
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
                            info!("HTTP POST Failed: {:?}", result);
                        }
                    }
                } else if syslog {
                    let syslog_string: Arc<String> = Arc::new(json_string.clone());
                    let result: Result<(), SyslogError> =
                        send_syslog(&hostname, &syslog_string, &syslog_address, &json, &debug)
                            .await;
                    match result {
                        Ok(()) => {}
                        Err(result) => {
                            info!("SYSLOG SEND Failed: {:?}", result);
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
                    &hostname,
                    user.name().to_string_lossy(),
                    data,
                    formatted_utc
                );
                if http {
                    let http_string: Arc<String> = Arc::new(string);
                    let result: Result<(), Error> =
                        send_http_post(client, &global_url, &http_string, &json, &debug).await;
                    match result {
                        Ok(()) => {}
                        Err(result) => {
                            info!("HTTP POST Failed: {:?}", result);
                        }
                    }
                } else if syslog {
                    let syslog_string: Arc<String> = Arc::new(string);
                    let result: Result<(), SyslogError> =
                        send_syslog(&hostname, &syslog_string, &syslog_address, &json, &debug)
                            .await;
                    match result {
                        Ok(()) => {}
                        Err(result) => {
                            info!("SYSLOG SEND Failed: {:?}", result);
                        }
                    }
                } else {
                    // this is the human readable output
                    info!("{}", string);
                }
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
                info!("Failed to connect to TCP syslog server: {:?}", e);
                return Err(e);
            }
        }
    } else if syslog_address.ends_with("/udp") {
        match syslog::udp(formatter, "0.0.0.0:0", host_and_port.to_string()) {
            Ok(w) => w,
            Err(e) => {
                info!("Failed to connect to UDP syslog server: {:?}", e);
                return Err(e);
            }
        }
    } else {
        match syslog::unix(formatter) {
            Ok(w) => w,
            Err(e) => {
                info!("Failed to connect to local syslog: {:?}", e);
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
                        info!("Error sending JSON to syslog: {:?}", e);
                        return Err(e);
                    }
                }
            }
            Err(e) => {
                info!("Invalid JSON: {:?}", e);
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
                info!("Error sending plaintext to syslog: {:?}", e);
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
                info!("{:?}", val);
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
                info!("Connection timed out");
            }
            _ => {
                info!("Unexpected error sending HTTP POST!");
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

pub async fn validate_url(url: &str) -> Result<&str, String> {
    // validate given URL
    if Url::parse(url).is_err() {
        Err(format!("\nInvalid URL '{}' provided", url))
    } else {
        Ok(url) // URL found valid
    }
}
