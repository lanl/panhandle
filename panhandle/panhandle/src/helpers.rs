use aya::maps::perf::{PerfEvent, PerfEventArrayBuffer};
use aya::programs::{KProbe};
use procfs::process::Process;
use tokio::{net::lookup_host, time::Duration};
extern crate simplelog;
use port_check::*;
use std::{fs::canonicalize, sync::Arc};
use url::Url;
use reqwest::{Client, Error, Response, header::CONTENT_TYPE};
use simplelog::{debug, error, info};
use syslog::{Error as SyslogError, Facility, Formatter3164};
use uzers::get_user_by_uid;
use chrono::prelude::*;

// this is the local import section
use panhandle_common::*;

// IMPLEMENTED: EbpfEvent trait provides generic event processing capabilities.
/// This trait enables unified handling of different eBPF event types (Readline, ExecveEvent, etc.)
/// through a common interface, allowing for code reuse between `consume_shell_ebpf_map` and
/// `consume_execve_ebpf_map` while maintaining type safety.
///
/// The trait provides methods to extract common event data for filtering, display, and processing.
///
/// # Examples
///
/// ```no_run
/// use panhandle::helpers::EbpfEvent;
/// use panhandle_common::Readline;
///
/// let event: Readline = /* ... */;
/// let filter_key = event.get_filter_key();
/// let command = event.get_command();
/// let uid = event.get_uid();
/// ```
pub trait EbpfEvent: Sized + std::fmt::Debug + std::fmt::Display {
    /// Extract the command or filename from the event for filtering purposes.
    ///
    /// For Readline events: returns the command string
    /// For ExecveEvent events: returns the filename string
    fn get_filter_key(&self) -> &str;
    
    /// Extract the command for display/output.
    ///
    /// Returns the command string associated with the event.
    fn get_command(&self) -> &str;
    
    /// Extract filename if available, returns None for shell events.
    ///
    /// Only implemented for ExecveEvent; Readline returns None.
    fn get_filename(&self) -> Option<&str> {
        None
    }
    
    /// Extract arguments if available, returns empty string for shell events.
    ///
    /// For ExecveEvent: returns command-line arguments as a joined string
    /// For Readline: returns empty string
    #[allow(dead_code)]
    fn get_args(&self) -> String {
        String::new()
    }
    
    /// Get the UID of the process that generated this event.
    fn get_uid(&self) -> u32;
    
    /// Get the PID of the process that generated this event.
    fn get_pid(&self) -> u32;
    
    /// Get the TGID (thread group ID) of the process that generated this event.
    fn get_tgid(&self) -> u32;
    
    /// Get the GID of the process that generated this event.
    fn get_gid(&self) -> u32;
}

// Implement EbpfEvent trait for Readline from panhandle-common
impl EbpfEvent for Readline {
    fn get_filter_key(&self) -> &str {
        core::str::from_utf8(&self.command)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .trim()
    }
    
    fn get_command(&self) -> &str {
        core::str::from_utf8(&self.command)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .trim()
    }
    
    fn get_uid(&self) -> u32 {
        self.uid
    }
    
    fn get_pid(&self) -> u32 {
        self.pid
    }
    
    fn get_tgid(&self) -> u32 {
        self.tgid
    }
    
    fn get_gid(&self) -> u32 {
        self.gid
    }
}

// Implement EbpfEvent trait for ExecveEvent from panhandle-common
impl EbpfEvent for ExecveEvent {
    fn get_filter_key(&self) -> &str {
        core::str::from_utf8(&self.filename)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .trim()
    }
    
    fn get_command(&self) -> &str {
        core::str::from_utf8(&self.command)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .trim()
    }
    
    fn get_filename(&self) -> Option<&str> {
        let filename = core::str::from_utf8(&self.filename)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .trim();
        if filename.is_empty() {
            None
        } else {
            Some(filename)
        }
    }
    
    fn get_args(&self) -> String {
        let mut args = String::new();
        for arg in &self.argv {
            let arg_str = core::str::from_utf8(arg)
                .unwrap_or_default()
                .trim_end_matches('\0')
                .trim();
            if !arg_str.is_empty() {
                if !args.is_empty() {
                    args.push(' ');
                }
                args.push_str(arg_str);
            }
        }
        args
    }
    
    fn get_uid(&self) -> u32 {
        self.uid
    }
    
    fn get_pid(&self) -> u32 {
        self.pid
    }
    
    fn get_tgid(&self) -> u32 {
        self.tgid
    }
    
    fn get_gid(&self) -> u32 {
        self.gid
    }
}

/// Unified event processor for both Readline and ExecveEvent types
/// This implements the TODO by providing a single generic function using the EbpfEvent trait.
/// Unified event processor for both Readline and ExecveEvent types.
/// Both consume_shell_ebpf_map and consume_execve_ebpf_map delegate to this implementation using the EbpfEvent trait.
pub fn consume_ebpf_map<T: EbpfEvent + Copy + 'static>(
    client: &Client,
    mut buf: PerfEventArrayBuffer<aya::maps::MapData>,
    ref_executable_vec: Vec<String>,
    global_url: Arc<String>,
    http: bool,
    syslog_address: Arc<String>,
    hostname: Arc<String>,
    syslog: bool,
    json: bool,
    debug: bool,
) {
    let client = client.clone();
    let global_url = global_url.clone();
    let syslog_address = syslog_address.clone();
    let hostname_ref = hostname.clone();
    let executable_vec = ref_executable_vec;

    buf.for_each(|event| {
        let sample_bytes = match event {
            PerfEvent::Sample { head, tail } => {
                let mut bytes = head.to_vec();
                bytes.extend_from_slice(tail);
                bytes
            }
            PerfEvent::Lost { count } => {
                error!("Lost {} events", count);
                return;
            }
        };
        
        // Deserialize the event data using the generic type T
        let ptr: *const T = sample_bytes.as_ptr() as *const T;
        // SAFETY: dereference the pointer that we created in ebpf-land
        // this is implemented by a shared struct and zero'd on the ebpf side for consistency
        let data: &T = unsafe { &*ptr };

        // Get the filter key and skip if matching exclusion list
        let filter_key = data.get_filter_key();
        if !executable_vec.is_empty() && !executable_vec.contains(&filter_key.to_string()) {
            debug!(
                "skipping event with path: '{}' not in the list to monitor: '{:?}'",
                filter_key, &executable_vec
            );
            return;
        }

        // Get user information
        let user_name = get_user_by_uid(data.get_uid()).map_or("unknown".to_string(), |u| u.name().to_string_lossy().into_owned());

        // Timestamp
        let utc: DateTime<Utc> = Utc::now();
        let formatted_utc = utc.format("%Y-%m-%d_%H:%M:%S").to_string();

        // Format and dispatch the event output
        let message = format_event_output::<T>(data, &hostname_ref, &user_name, &formatted_utc, json);
        dispatch_event_output(
            message,
            &client,
            &global_url,
            http,
            syslog,
            &syslog_address,
            &hostname_ref,
            json,
            debug,
        );
    });
}

/// Helper function to generate formatted output for any EbpfEvent type
fn format_event_output<T: EbpfEvent + 'static>(
    data: &T,
    hostname: &str,
    user_name: &str,
    timestamp: &str,
    json: bool,
) -> String {
    if json {
        // For ExecveEvent, include filename, args, and envs
        if let Some(execve_data) = (data as &dyn std::any::Any).downcast_ref::<ExecveEvent>() {
            let mut envvec: Vec<String> = Vec::new();
            for env_ptr in &execve_data.envp {
                let mut env = core::str::from_utf8(env_ptr).unwrap_or_default().trim();
                if !env.starts_with('\0') {
                    if let Some((prefix, _)) = env.split_once("\0") {
                        env = prefix;
                    }
                    envvec.push(env.trim_end_matches('\0').to_string());
                }
            }
            
            let mut argvec: Vec<String> = Vec::new();
            for arg_ptr in &execve_data.argv {
                let mut arg = core::str::from_utf8(arg_ptr).unwrap_or_default().trim();
                if !arg.starts_with('\0') {
                    if let Some((prefix, _)) = arg.split_once("\0") {
                        arg = prefix;
                    }
                    argvec.push(arg.trim_end_matches('\0').to_string());
                }
            }
            
            format!(
                "{{\"application\": \"panhandle\", \"hostname\": \"{}\", \"moniker\": \"{}\", \"filename\": \"{}\", \"command\": \"{}\", \"uid\": {}, \"pid\": {}, \"gid\": {}, \"tgid\": {}, \"args\": {:?}, \"envs\": {:?}, \"ts_utc\": \"{}\"}}",
                hostname,
                user_name,
                execve_data.get_filename().unwrap_or_default(),
                execve_data.get_command(),
                execve_data.get_uid(),
                execve_data.get_pid(),
                execve_data.get_gid(),
                execve_data.get_tgid(),
                argvec,
                envvec,
                timestamp
            )
        } else if let Some(readline_data) = (data as &dyn std::any::Any).downcast_ref::<Readline>() {
            // For Readline events, include entry and command
            format!(
                "{{\"application\": \"panhandle\", \"hostname\": \"{}\", \"moniker\": \"{}\", \"entry\": \"{}\", \"command\": \"{}\", \"uid\": {}, \"pid\": {}, \"gid\": {}, \"tgid\": {}, \"ts_utc\": \"{}\"}}",
                hostname,
                user_name,
                core::str::from_utf8(&readline_data.entry).unwrap_or_default().trim_end_matches('\0').trim(),
                readline_data.get_command(),
                readline_data.get_uid(),
                readline_data.get_pid(),
                readline_data.get_gid(),
                readline_data.get_tgid(),
                timestamp
            )
        } else {
            // Fallback for other types
            format!(
                "{{\"application\": \"panhandle\", \"hostname\": \"{}\", \"moniker\": \"{}\", \"command\": \"{}\", \"uid\": {}, \"pid\": {}, \"gid\": {}, \"tgid\": {}, \"ts_utc\": \"{}\"}}",
                hostname,
                user_name,
                data.get_command(),
                data.get_uid(),
                data.get_pid(),
                data.get_gid(),
                data.get_tgid(),
                timestamp
            )
        }
    } else {
        // Plain text output
        format!(
            "application: panhandle, hostname: {}, moniker: {}, {}, ts_utc: '{}'",
            hostname,
            user_name,
            data,
            timestamp
        )
    }
}

/// Helper function to dispatch event output to appropriate destinations
fn dispatch_event_output(
    message: String,
    client: &Client,
    global_url: &Arc<String>,
    http: bool,
    syslog: bool,
    syslog_address: &Arc<String>,
    hostname: &Arc<String>,
    json: bool,
    debug: bool,
) {
    if syslog {
        let syslog_string = Arc::new(message.clone());
        let hostname_clone = hostname.clone();
        let syslog_address_clone = syslog_address.clone();
        tokio::spawn(async move {
            if let Err(e) = send_syslog(&hostname_clone, &syslog_string, &syslog_address_clone, &json, &debug).await {
                error!("SYSLOG SEND Failed: {:?}", e);
            }
        });
    }

    if http {
        let http_string = Arc::new(message.clone());
        let client_clone = client.clone();
        let global_url_clone = global_url.clone();
        tokio::spawn(async move {
            if let Err(e) = send_http_post(&client_clone, &global_url_clone, &http_string, &json, &debug).await {
                error!("HTTP POST Failed: {:?}", e);
            }
        });
    }

    if debug {
        info!("{:#?}", message);
    } else {
        info!("{}", message);
    }
}



/// this is a method to handle the display of the shell (bash, zsh) ebpf events
/// Delegates to the unified consume_ebpf_map function for generic processing
pub fn consume_shell_ebpf_map(
    client: &Client,
    buf: PerfEventArrayBuffer<aya::maps::MapData>,
    ref_executable_vec: Vec<String>,
    global_url: Arc<String>,
    http: bool,
    syslog_address: Arc<String>,
    hostname: Arc<String>,
    syslog: bool,
    json: bool,
    debug: bool,
) {
    // Delegate to the unified function with Readline as the concrete type
    consume_ebpf_map::<Readline>(
        client,
        buf,
        ref_executable_vec,
        global_url,
        http,
        syslog_address,
        hostname,
        syslog,
        json,
        debug,
    );
}

/// this is a method to handle the display of the execve ebpf events
/// Delegates to the unified consume_ebpf_map function for generic processing
pub fn consume_execve_ebpf_map(
    client: &Client,
    buf: PerfEventArrayBuffer<aya::maps::MapData>,
    ref_executable_vec: Vec<String>,
    global_url: Arc<String>,
    http: bool,
    syslog_address: Arc<String>,
    hostname: Arc<String>,
    syslog: bool,
    json: bool,
    debug: bool,
) {
    // Delegate to the unified function with ExecveEvent as the concrete type
    consume_ebpf_map::<ExecveEvent>(
        client,
        buf,
        ref_executable_vec,
        global_url,
        http,
        syslog_address,
        hostname,
        syslog,
        json,
        debug,
    );
}

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
                "Completed http request with response code: {:#?}",
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

pub async fn validate_url(url: &str) -> Result<&str, String> {
    // validate given URL
    if Url::parse(url).is_err() {
        Err(format!("\nInvalid URL '{}' provided", url))
    } else {
        Ok(url) // URL found valid
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
    } else {
        info!("{}", plain_string);
    }
}

/// Helper function to attach a single kprobe
pub fn attach_kprobe(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
) -> Result<(), anyhow::Error> {
    let program: &mut KProbe = ebpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow::anyhow!("Program '{}' not found", program_name))?
        .try_into()?;
    
    program.load()?;
    program.attach(program_name, 0)?;
    
    Ok(())
}

/// Get process name from PID
pub fn get_process_name(pid: u32) -> Option<String> {
    Process::new(pid as i32)
        .ok()
        .and_then(|proc| proc.stat().ok())
        .map(|stat| stat.comm)
}

// TODO: This function is not currently used but may be needed for future monitoring features
// such as process tree analysis or parent-child relationship tracking.
#[allow(dead_code)]
/// Get the parent PID for a given PID
pub fn get_parent_pid(pid: u32) -> Result<u32, Box<dyn std::error::Error>> {
    let proc = Process::new(pid as i32)?;
    let stat = proc.stat()?;
    Ok(stat.ppid as u32)
}