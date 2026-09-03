use std::{
    convert::TryInto,
    fs::{File, canonicalize},
    panic,
    path::PathBuf,
    process,
    sync::Arc,
};

use aya::{
    Btf,
    maps::{HashMap, RingBuf},
    programs::{BtfTracePoint, TracePoint, UProbe, uprobe::UProbeScope},
};
use aya_log::EbpfLogger; // uncomment to see ebpf side logging for cpu monitoring
use clap::Parser;
use machine_info::Machine;
use reqwest::Client;
use simplelog::*;
use tokio::{
    io::{Interest, unix::AsyncFd},
    signal,
    task::JoinHandle,
    time::{Duration, sleep},
};
use uzers::get_current_uid;

#[rustfmt::skip]
// this is the local import section
mod helpers;
mod input_configs;
mod monitor_cpu_usage;
mod monitor_gpu_usage;
mod monitor_io_usage;
mod monitor_network_usage;
mod procfs_helpers;
mod unit_tests;
use helpers::*;
use input_configs::*;
use monitor_cpu_usage::*;
use monitor_gpu_usage::*;
use monitor_io_usage::*;
use monitor_network_usage::*;
use panhandle_common::*;

/// Validate every user-controlled numeric/list argument up front, before the
/// root-privilege check and eBPF load later in `main`. Doing this early means
/// startup fails fast on bad input (a typo'd config, an oversized list) without
/// first requiring root or a working eBPF-capable kernel - and it's what makes
/// these failure modes reachable by a plain subprocess integration test rather
/// than only by a root-gated one. The actual (re-)validation deeper in `main`,
/// right before each value is used to populate an eBPF map, is left in place;
/// this function's checks are strictly redundant with it for a process that
/// gets this far, but cheap and worth keeping as defense in depth.
fn validate_args_or_exit(args: &RawArgs) {
    // clap's value_parser (range(1..)) only rejects 0 when --poll comes from the CLI;
    // a config-file poll: 0 has no serde-level equivalent and would otherwise reach
    // Duration::from_secs(0), spinning every enabled monitor loop with no delay.
    if let Some(poll) = args.poll
        && poll == 0
    {
        eprintln!("--poll must be at least 1 (got 0)");
        process::exit(1);
    }

    // Compare the effective range (defaults applied) rather than only the fields that
    // were actually set, so e.g. --exclude-min-uid 1000 with --exclude-max-uid left at
    // its default of 999 is still caught, not just the both-explicitly-set case. An
    // inverted range would otherwise silently exclude nothing instead of what the user
    // presumably meant to exclude.
    let effective_min_uid = args.exclude_min_uid.unwrap_or(MINUID);
    let effective_max_uid = args.exclude_max_uid.unwrap_or(MAXUID);
    if effective_min_uid > effective_max_uid {
        eprintln!(
            "--exclude-min-uid ({}) must not be greater than --exclude-max-uid ({})",
            effective_min_uid, effective_max_uid
        );
        process::exit(1);
    }

    if let Some(ref executables) = args.executables {
        let canonical = get_canonical_executable_list(executables);
        if let Err(e) = validate_count(canonical.len(), EXECUTABLE_COUNT, "executables") {
            eprintln!("{}", e);
            process::exit(1);
        }
    }

    if let Some(ref include_uid) = args.include_uid {
        for uid_string in include_uid {
            if uid_string.parse::<u32>().is_err() {
                eprintln!(
                    "Invalid --include-uid value '{}': must be a non-negative integer",
                    uid_string
                );
                process::exit(1);
            }
        }
        if let Err(e) = validate_count(include_uid.len(), UID_COUNT, "UIDs") {
            eprintln!("{}", e);
            process::exit(1);
        }
    }

    if args.syscalls.is_some() {
        let (_, comms) = match resolve_comm_list_mode(&args.comm_deny, &args.comm_allow) {
            Ok(resolved) => resolved,
            Err(e) => {
                eprintln!("{}", e);
                process::exit(1);
            }
        };
        if let Err(e) = validate_count(
            comms.len(),
            MAX_BLOCKED_COMMS,
            "comm-allow/comm-deny entries",
        ) {
            eprintln!("{}", e);
            process::exit(1);
        }
        for comm in &comms {
            if let Err(e) = validate_comm_length(comm) {
                eprintln!("{}", e);
                process::exit(1);
            }
        }
        if let Some(ref paths) = args.block_paths {
            if let Err(e) = validate_count(paths.len(), MAX_BLOCKED_PATHS, "block-paths entries") {
                eprintln!("{}", e);
                process::exit(1);
            }
            for path in paths {
                if let Err(e) = validate_path_length(path) {
                    eprintln!("{}", e);
                    process::exit(1);
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // load_args function in input_config.rs
    let mut cli_args = RawArgs::parse();

    let args = if let Some(config) = cli_args.config.take() {
        let config_args = match load_config_args(config).await {
            Ok(returned_args) => returned_args,
            Err(e) => {
                eprintln!("{}", e);
                process::exit(1);
            }
        };
        merge_args(cli_args, config_args).await
    } else {
        cli_args // if no config provided, just move forward using given cli args
    };

    if args.verbose {
        println!("Starting Panhandle, using the arguments: \n{:#?}", args);
    }

    validate_args_or_exit(&args);

    // remove standard backtrace message if not debug
    if !args.debug {
        panic::set_hook(Box::new(|_| {}));
    }

    // check for if running as root, exit if not
    let current_uid = get_current_uid();
    if current_uid != 0 {
        println!("Panhandle must run as root, exiting with error");
        process::exit(1);
    }

    // Determine the log filter level based on the debug arg:
    let log_filter_level = if args.debug {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    // declare output-related variables before using them in output parsing
    let global_url: Arc<String>;
    let syslog_address: Arc<String>;
    let http_bool: bool;
    let syslog_bool: bool;

    let term_logger = TermLogger::new(
        log_filter_level,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .set_time_offset_to_local()
            .unwrap()
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    );

    // check output args: --syslog, --http, and --file
    match args.output {
        Some(OutputCommand::Output { file, http, syslog }) => {
            // parse the http subcommand
            http_bool = http.is_some();
            global_url = if http_bool {
                let url = http.clone().unwrap();
                match validate_url(url.as_str()).await {
                    Ok(_) => Arc::new(url),
                    Err(e) => {
                        eprintln!("{}", e);
                        process::exit(1)
                    }
                }
            } else {
                Arc::new("".to_string())
            };
            // parse the syslog subcommand
            syslog_bool = syslog.is_some();
            syslog_address = if let Some(inner) = syslog {
                // inner is Option<String>
                match inner {
                    Some(addr) => Arc::new(addr.clone()), // --syslog unix or --syslog /dev/log
                    None => Arc::new(String::from("/dev/log")), // plain --syslog <nothing>, give it /dev/log as a placeholder
                }
            } else {
                Arc::new("".to_string()) // syslog flag not provided
            };

            // validate syslog address
            if syslog_bool {
                match validate_syslog(syslog_address.as_str()).await {
                    Ok(_) => (),
                    Err(e) => {
                        eprintln!("{}", e);
                        process::exit(1);
                    }
                }
            }

            // Set up logging, either to a file or terminal based on args:
            if let Some(path) = file {
                let file: File = File::options().append(true).create(true).open(&path)?;
                if args.debug {
                    println!("log file: {}", path.display());
                }

                let logger = WriteLogger::new(log_filter_level, simplelog::Config::default(), file);
                // combined logger has to include the write logger in this case as well as a possible terminal logger
                if !args.quiet {
                    CombinedLogger::init(vec![logger, term_logger]).unwrap();
                } else {
                    CombinedLogger::init(vec![logger]).unwrap();
                }
            } else {
                // use the terminal logger if the file option is not specified
                // and if the quiet option is also not specified
                if !args.quiet {
                    CombinedLogger::init(vec![term_logger]).unwrap();
                }
            }
        }
        // no output provided, so default all output-related vars
        None => {
            global_url = Arc::new("".to_string());
            syslog_address = Arc::new("".to_string());
            http_bool = false;
            syslog_bool = false;
            if !args.quiet {
                CombinedLogger::init(vec![term_logger]).unwrap();
            }
        }
    }

    // grab hostname and convert to Arc string
    let hostname = match hostname::get() {
        Ok(os_str) => match os_str.into_string() {
            Ok(name) => Arc::new(name),
            Err(_) => Arc::new("UNKOWN_HOST".to_string()),
        },
        Err(_) => Arc::new("UNKNOWN_HOST".to_string()),
    };

    // load the built ebpf program
    // this looks like a failure until the ebpf build runs
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/panhandle"
    )))?;

    if args.debug {
        match EbpfLogger::init(&mut ebpf) {
            Ok(logger) => match AsyncFd::with_interest(logger, Interest::READABLE) {
                Ok(mut async_logger) => {
                    tokio::spawn(async move {
                        loop {
                            let Ok(mut guard) = async_logger.readable_mut().await else {
                                continue;
                            };
                            guard.get_inner_mut().flush();
                            guard.clear_ready();
                        }
                    });
                }
                Err(e) => eprintln!("failed to poll eBPF logger: {e}"),
            },
            // not fatal — just means you won't see ebpf-side logs
            Err(e) => eprintln!("failed to initialize eBPF logger: {e}"),
        }
    }

    // set up executable vars
    let mut canonical_executable_vec = Vec::new();
    if let Some(executables) = args.executables {
        canonical_executable_vec.append(&mut get_canonical_executable_list(&executables));
        if let Err(e) = validate_count(
            canonical_executable_vec.len(),
            EXECUTABLE_COUNT,
            "executables",
        ) {
            info!("{}", e);
            process::exit(1);
        };
    };

    // set up include uids
    let include_uid_bool = args.include_uid.is_some();
    let only_these_uids_vec: Vec<u32> = match args.include_uid {
        Some(inc) => {
            let mut uids = Vec::with_capacity(inc.len());
            for uid_string in &inc {
                match uid_string.parse::<u32>() {
                    Ok(uid) => uids.push(uid),
                    Err(_) => {
                        info!(
                            "Invalid --include-uid value '{}': must be a non-negative integer",
                            uid_string
                        );
                        process::exit(1);
                    }
                }
            }
            uids
        }
        None => Vec::new(),
    };

    if let Err(e) = validate_count(only_these_uids_vec.len(), UID_COUNT, "UIDs") {
        info!("{}", e);
        process::exit(1);
    }

    // polling frequency variable for performance monitoring tasks
    let mut polling_freq_seconds: u32 = 30; // default interval is 30 seconds; if changed, be sure to reflect the change in input_config.rs
    if let Some(poll) = args.poll {
        polling_freq_seconds = poll;
    }

    // move to if statements for the main program args
    // goal is to try to allow a combination of all of the args
    // this introduces some code duplication
    // CPU monitoring
    let mut cpu_handle: Option<JoinHandle<()>> = None;
    if args.cpu {
        let json_output = args.json;
        let debug_mode = args.debug;
        let verbose_mode = args.verbose;

        // Clone necessary variables for the async task
        let url = global_url.clone();
        let host = hostname.clone();
        let syslog = syslog_address.clone();
        let client = Client::new();
        let pid_filter = args.pid_list.clone();

        // Spawn CPU monitoring task
        cpu_handle = Some(tokio::spawn(async move {
            use std::collections::HashMap as StdHashMap;

            let mut last_total_busy: Option<u64> = None;
            let mut last_pid_times: StdHashMap<u32, u64> = StdHashMap::new();
            let mut pid_stats: StdHashMap<u32, PidStats> = StdHashMap::new();
            let mut sample_count = 0u64;

            loop {
                if let Err(e) = monitor_cpu_usage(
                    &pid_filter,
                    &json_output,
                    &http_bool,
                    &syslog_bool,
                    &verbose_mode,
                    &host,
                    &syslog,
                    &url,
                    &client,
                    &debug_mode,
                    &mut last_total_busy,
                    &mut last_pid_times,
                    &mut pid_stats,
                    &mut sample_count,
                    polling_freq_seconds,
                )
                .await
                {
                    error!("CPU monitoring error: {}", e);
                }
                let _ = sleep(Duration::from_secs(polling_freq_seconds.into())).await;
            }
        }));
    }

    // GPU monitoring
    let mut gpu_handle: Option<JoinHandle<()>> = None;
    if args.gpu {
        let json_output = args.json;
        let debug_mode = args.debug;
        let verbose_mode = args.verbose;
        let url = global_url.clone();
        let host = hostname.clone();
        let syslog = syslog_address.clone();
        let client = Client::new();
        let pid_filter = args.pid_list.clone();
        let machine = Machine::new();
        gpu_handle = Some(tokio::spawn(async move {
            loop {
                if let Err(e) = monitor_gpu_usage(
                    &machine,
                    &json_output,
                    &http_bool,
                    &syslog_bool,
                    &debug_mode,
                    &verbose_mode,
                    &host,
                    &syslog,
                    &url,
                    &client,
                    &pid_filter,
                )
                .await
                {
                    error!("GPU monitoring error {}", e);
                }
                let _ = sleep(Duration::from_secs(polling_freq_seconds.into())).await;
            }
        }));
    }

    // Network monitoring
    let mut socket_handle: Option<JoinHandle<()>> = None;
    if args.socket {
        let btf = Btf::from_sys_fs()?;

        // Attach all network monitoring programs
        let program: &mut BtfTracePoint = ebpf
            .program_mut("inet_sock_set_state")
            .unwrap()
            .try_into()
            .inspect_err(|e| error!("failed to load eBPF program 'inet_sock_set_state': {}", e))?;
        program.load("inet_sock_set_state", &btf).inspect_err(|e| {
            error!("failed to load BTF tracepoint 'inet_sock_set_state': {}", e)
        })?;
        program.attach().inspect_err(|e| {
            error!(
                "failed to attach BTF tracepoint 'inet_sock_set_state': {}",
                e
            )
        })?;
        debug!("attached eBPF BTF tracepoint 'inet_sock_set_state'");

        // Attach kprobes for data transfer tracking
        attach_kprobe(&mut ebpf, "tcp_sendmsg")?;
        attach_kprobe(&mut ebpf, "tcp_cleanup_rbuf")?;
        attach_kprobe(&mut ebpf, "udp_sendmsg")?;
        attach_kprobe(&mut ebpf, "udp_recvmsg")?;

        // Socket probes stream per-event deltas over a ring buffer rather than
        // maintaining shared aggregate state on the kernel side (see socket.rs for
        // why); this userspace-owned map accumulates them, and monitor_network_usage
        // both reads and prunes it.
        let net_stats: SharedNetStats =
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

        let socket_ring_buf =
            RingBuf::try_from(ebpf.take_map("socket_events").ok_or_else(|| {
                format!(
                    "eBPF map '{}' not found in loaded object - binary/eBPF build mismatch?",
                    "socket_events"
                )
            })?)?;
        let socket_async_fd = AsyncFd::with_interest(socket_ring_buf, Interest::READABLE)?;
        let net_stats_consumer = net_stats.clone();
        tokio::task::spawn(consume_socket_stats_ebpf_map(
            socket_async_fd,
            net_stats_consumer,
        ));

        let json_output = args.json;
        let debug_mode = args.debug;
        let verbose_mode = args.verbose;

        // Clone necessary variables for the async task
        let url = global_url.clone();
        let host = hostname.clone();
        let syslog = syslog_address.clone();
        let client = Client::new();
        let pid_filter = args.pid_list.clone();

        // Spawn network monitoring task
        socket_handle = Some(tokio::spawn(async move {
            loop {
                if let Err(e) = monitor_network_usage(
                    &net_stats,
                    &json_output,
                    &http_bool,
                    &syslog_bool,
                    &debug_mode,
                    &verbose_mode,
                    &host,
                    &syslog,
                    &url,
                    &client,
                    &pid_filter,
                )
                .await
                {
                    error!("Network monitoring error: {}", e);
                }
                let _ = sleep(Duration::from_secs(polling_freq_seconds.into())).await;
            }
        }));
    }

    // using procfs for IO monitoring
    let mut io_handle: Option<JoinHandle<()>> = None;

    if args.io {
        let json_output = args.json;
        let debug_mode = args.debug;
        let verbose_mode = args.verbose;
        let url = global_url.clone();
        let host = hostname.clone();
        let syslog = syslog_address.clone();
        let client = Client::new();
        let pid_filter = args.pid_list.clone();

        io_handle = Some(tokio::spawn(async move {
            loop {
                if let Err(e) = monitor_io_usage(
                    &json_output,
                    &http_bool,
                    &syslog_bool,
                    &debug_mode,
                    &verbose_mode,
                    &host,
                    &syslog,
                    &url,
                    &client,
                    &pid_filter,
                )
                .await
                {
                    error!("IO monitoring error: {}", e);
                }
                let _ = sleep(Duration::from_secs(polling_freq_seconds.into())).await;
            }
        }));
    }

    // set up the memory fault monitoring
    let mut memory_fault_handle: Option<JoinHandle<()>> = None;

    if let Some(threshold_fault_count) = args.memory_faults {
        let url = global_url.clone();
        let host = hostname.clone();
        let syslog = syslog_address.clone();
        let verbose_mode = args.verbose;
        let client = Client::new();

        memory_fault_handle = Some(tokio::task::spawn(async move {
            loop {
                let _ = procfs_helpers::get_major_faults(
                    threshold_fault_count,
                    &args.json,
                    &http_bool,
                    &syslog_bool,
                    &verbose_mode,
                    &host,
                    &url,
                    &syslog,
                    &client,
                    &args.debug,
                )
                .await;
                let _ = sleep(Duration::from_secs(polling_freq_seconds.into())).await;
            }
        }));
    }

    // set up the memory usage monitoring
    let mut memory_usage_handle: Option<JoinHandle<()>> = None;
    if args.memory {
        let url = global_url.clone();
        let host = hostname.clone();
        let syslog = syslog_address.clone();
        let verbose_mode = args.verbose;
        let pid_filter = args.pid_list.clone();

        let client = Client::new();
        memory_usage_handle = Some(tokio::task::spawn(async move {
            loop {
                let _ = procfs_helpers::get_all_memory_usage(
                    &args.json,
                    &http_bool,
                    &syslog_bool,
                    &verbose_mode,
                    &host,
                    &url,
                    &syslog,
                    &client,
                    &args.debug,
                    &pid_filter,
                )
                .await;
                let _ = sleep(Duration::from_secs(polling_freq_seconds.into())).await;
            }
        }));
    }

    // process syscall blocking
    if let Some(syscalls) = &args.syscalls {
        // Not allowing for providing both an allow list and deny list
        let (list_type, comms) = match resolve_comm_list_mode(&args.comm_deny, &args.comm_allow) {
            Ok(resolved) => resolved,
            Err(e) => {
                info!("{}", e);
                process::exit(1);
            }
        };
        if list_type == NO_LIST && args.verbose {
            info!(
                "Syscall blocking enabled but no deny/allow comm list specified. No processes will be blocked."
            );
        }

        // clap's num_args upper bound only limits raw CLI tokens, not the values a
        // single comma-separated argument splits into, so it can't reject an over-limit
        // list at parse time -- enforce the documented maximums here instead.
        if let Err(e) = validate_count(
            comms.len(),
            MAX_BLOCKED_COMMS,
            "comm-allow/comm-deny entries",
        ) {
            info!("{}", e);
            process::exit(1);
        }
        // clap's value_parser only validates comm-allow/comm-deny supplied on the CLI,
        // not ones coming from the config file -- enforce the same length limit here
        // so an over-long config entry is rejected instead of silently truncated below.
        for comm in &comms {
            if let Err(e) = validate_comm_length(comm) {
                info!("{}", e);
                process::exit(1);
            }
        }
        if let Some(ref paths) = args.block_paths
            && let Err(e) = validate_count(paths.len(), MAX_BLOCKED_PATHS, "block-paths entries")
        {
            info!("{}", e);
            process::exit(1);
        }
        // clap's value_parser only validates block-paths supplied on the CLI, not
        // ones coming from the config file -- enforce the same length limit here so
        // an over-long config entry can't overflow the fixed-size eBPF map key below.
        if let Some(ref paths) = args.block_paths {
            for path in paths {
                if let Err(e) = validate_path_length(path) {
                    info!("{}", e);
                    process::exit(1);
                }
            }
        }

        let blocked_paths: Vec<String> = if let Some(ref paths) = args.block_paths {
            paths.clone()
        } else {
            Vec::new()
        };

        // Get the COMMS map
        let comms_map = ebpf.take_map("COMMS").ok_or_else(|| {
            format!(
                "eBPF map '{}' not found in loaded object - binary/eBPF build mismatch?",
                "COMMS"
            )
        })?;
        let mut comm_list: aya::maps::HashMap<_, [u8; 16], u8> =
            aya::maps::HashMap::try_from(comms_map)?;

        // list_type is used on the ebpf side to determine how to handle process blocking
        for comm_str in comms {
            let mut comm = [0u8; 16];
            let bytes = comm_str.as_bytes();
            let len = bytes.len().min(15); // Already validated above to be <= MAX_COMM_LENGTH (15); min() is just a defensive clamp
            comm[..len].copy_from_slice(&bytes[..len]);
            comm_list.insert(comm, list_type, 0)?;
        }

        // Insert mode indicator key to tell eBPF which mode we're in.
        // This known key within the hashmap is required for when ebpf side can't find a comm in the map but still needs to know what to do with it
        if list_type != NO_LIST {
            let mode_key = [LIST_MODE; 16];
            comm_list.insert(mode_key, list_type, 0)?;
        }

        // Get the BLOCKED_PATHS map
        let blocked_paths_map = ebpf.take_map("BLOCKED_PATHS").ok_or_else(|| {
            format!(
                "eBPF map '{}' not found in loaded object - binary/eBPF build mismatch?",
                "BLOCKED_PATHS"
            )
        })?;
        let mut path_denylist: aya::maps::HashMap<_, [u8; 256], u8> =
            aya::maps::HashMap::try_from(blocked_paths_map)?;

        // Populate the denylist with initial paths
        if blocked_paths.is_empty() {
            let path = [0u8; 256];
            path_denylist.insert(path, 0, 0)?; // value of 0 is a placeholder, check on ebpf side for it to know that no path list was provided
            if args.verbose {
                println!(
                    "Process blocking was turned on but no filepath list was provided. Defaulting to blocking all paths."
                )
            }
        }
        for path_str in blocked_paths {
            let mut path = [0u8; 256];
            let bytes = path_str.as_bytes();
            let len = bytes.len(); // Already validated above (CLI value_parser or the config-file check) to be <= MAX_PATH_LENGTH (255)
            path[..len].copy_from_slice(&bytes[..len]);
            path_denylist.insert(path, 1, 0)?;
        }

        // Check for open related syscalls - open, openat, creat
        if syscalls
            .iter()
            .any(|s| s == "open" || s == "openat" || s == "creat")
        {
            attach_lsm_hook(&mut ebpf, "file_open", "block_open")
                .expect("failed to attach file_open hook");
        }

        if syscalls.iter().any(|s| s == "execve") {
            attach_lsm_hook(&mut ebpf, "bprm_check_security", "block_execve")
                .expect("failed to attach bprm_check_security hook");
        }
    }

    if args.bash {
        // canonicalize the path and then convert to string
        let file: PathBuf = canonicalize("/bin/bash").unwrap_or_default();
        if !file.exists() {
            error!("Could not find /bin/bash");
            process::exit(1);
        }
        debug!("found executable: {:?}", file);
        let file_string = file.into_os_string().into_string().unwrap_or_else(|os| {
            error!("Path to bash is not valid UTF-8: {:?}", os);
            process::exit(1);
        });
        debug!(
            "converted PathBuf path to this file string: '{}'",
            file_string
        );

        // readline stuff
        let program: &mut UProbe = ebpf
            .program_mut("readline")
            .unwrap()
            .try_into()
            .inspect_err(|e| error!("failed to load eBPF program 'readline': {}", e))?;
        program
            .load()
            .inspect_err(|e| error!("failed to load uprobe 'readline': {}", e))?;
        program
            .attach(
                "readline_internal_teardown",
                &file_string,
                UProbeScope::AllProcesses,
            )
            .inspect_err(|e| {
                error!(
                    "failed to attach uprobe 'readline' to '{}': {}",
                    file_string, e
                )
            })?;
        debug!("attached eBPF uprobe 'readline' to '{}'", file_string);

        // get the uid_options map from ebpf land
        let readline_uid_options_map = ebpf.take_map("readline_uid_options").ok_or_else(|| {
            format!(
                "eBPF map '{}' not found in loaded object - binary/eBPF build mismatch?",
                "readline_uid_options"
            )
        })?;
        let mut program_options: HashMap<_, u32, u32> =
            HashMap::try_from(readline_uid_options_map).unwrap();
        // add the data as u32s to the map by index / the values will be retrieved by index in ebpf-land so the index is hard-coded
        // this is the shells identifier
        program_options.insert(UID_OPT_SHELLS, args.shells as u32, 0)?;
        // this is the min uid identifier
        program_options.insert(
            UID_OPT_EXCLUDE_MIN,
            args.exclude_min_uid.unwrap_or(MINUID),
            0,
        )?;
        // this is the max uid identifier
        program_options.insert(
            UID_OPT_EXCLUDE_MAX,
            args.exclude_max_uid.unwrap_or(MAXUID),
            0,
        )?;
        // this is the include uid list option identifier
        program_options.insert(UID_OPT_INCLUDE_ENABLED, include_uid_bool as u32, 0)?;

        // get the uid_include_list map from ebpf land
        let readline_uid_include_list_map =
            ebpf.take_map("readline_uid_include_list").ok_or_else(|| {
                format!(
                    "eBPF map '{}' not found in loaded object - binary/eBPF build mismatch?",
                    "readline_uid_include_list"
                )
            })?;
        let mut readline_uid_list_map: HashMap<_, u32, [u32; UID_COUNT]> =
            HashMap::try_from(readline_uid_include_list_map).unwrap();
        // set up defaults of a zero'd array
        let mut zeroed_array: [u32; UID_COUNT] = [0; UID_COUNT];

        if include_uid_bool {
            for (uid_list_counter, value) in only_these_uids_vec.iter().enumerate() {
                zeroed_array[uid_list_counter] = *value;
            }
            debug!("array of specific uids to watch: {:?}", zeroed_array);
        }

        // add the data to the map by index / the values will be retrieved by index in ebpf-land
        readline_uid_list_map.insert(0, zeroed_array, 0)?;

        // Process events from the ring buffer
        let ring_buf = RingBuf::try_from(ebpf.take_map("readline_events").ok_or_else(|| {
            format!(
                "eBPF map '{}' not found in loaded object - binary/eBPF build mismatch?",
                "readline_events"
            )
        })?)?;
        let async_fd = AsyncFd::with_interest(ring_buf, Interest::READABLE)?;

        let ref_executable_vec: Vec<String> = canonical_executable_vec.clone();
        let ref_global_url = global_url.clone();
        let ref_syslog_address = syslog_address.clone();
        let client = Client::new();
        let ref_hostname = hostname.clone();

        // now spawn the async stuff
        tokio::task::spawn(async move {
            consume_shell_ebpf_map(
                &client,
                async_fd,
                ref_executable_vec,
                ref_global_url,
                http_bool,
                ref_syslog_address,
                ref_hostname,
                syslog_bool,
                args.json,
                args.debug,
            )
            .await;
        });
    }
    if args.zsh {
        // canonicalize the path and then convert to string
        let file: PathBuf = canonicalize("/bin/zsh").unwrap_or_default();
        if !file.exists() {
            error!("Could not find /bin/zsh");
            process::exit(1);
        }
        debug!("found executable: {:?}", file);
        let file_string = file.into_os_string().into_string().unwrap_or_else(|os| {
            error!("Path to zsh is not valid UTF-8: {:?}", os);
            process::exit(1);
        });
        debug!(
            "converted PathBuf path to this file string: '{}'",
            file_string
        );

        // zlentry stuff
        let program: &mut UProbe = ebpf
            .program_mut("zlentry")
            .unwrap()
            .try_into()
            .inspect_err(|e| error!("failed to load eBPF program 'zlentry': {}", e))?;
        program
            .load()
            .inspect_err(|e| error!("failed to load uprobe 'zlentry': {}", e))?;
        program
            .attach("zleentry", &file_string, UProbeScope::AllProcesses)
            .inspect_err(|e| {
                error!(
                    "failed to attach uprobe 'zlentry' to '{}': {}",
                    file_string, e
                )
            })?;
        debug!("attached eBPF uprobe 'zlentry' to '{}'", file_string);

        // get the uid_options map from ebpf land
        let zlentry_uid_options_map = ebpf.take_map("zlentry_uid_options").ok_or_else(|| {
            format!(
                "eBPF map '{}' not found in loaded object - binary/eBPF build mismatch?",
                "zlentry_uid_options"
            )
        })?;
        let mut program_options: HashMap<_, u32, u32> =
            HashMap::try_from(zlentry_uid_options_map).unwrap();
        // add the data as u32s to the map by index / the values will be retrieved by index in ebpf-land so the index is hard-coded
        // this is the shells identifier
        program_options.insert(UID_OPT_SHELLS, args.shells as u32, 0)?;
        // this is the min uid identifier
        program_options.insert(
            UID_OPT_EXCLUDE_MIN,
            args.exclude_min_uid.unwrap_or(MINUID),
            0,
        )?;
        // this is the max uid identifier
        program_options.insert(
            UID_OPT_EXCLUDE_MAX,
            args.exclude_max_uid.unwrap_or(MAXUID),
            0,
        )?;
        // this is the include uid list option identifier
        program_options.insert(UID_OPT_INCLUDE_ENABLED, include_uid_bool as u32, 0)?;

        // get the uid_include_list map from ebpf land
        let zlentry_uid_include_list_map =
            ebpf.take_map("zlentry_uid_include_list").ok_or_else(|| {
                format!(
                    "eBPF map '{}' not found in loaded object - binary/eBPF build mismatch?",
                    "zlentry_uid_include_list"
                )
            })?;
        let mut zlentry_uid_list_map: HashMap<_, u32, [u32; UID_COUNT]> =
            HashMap::try_from(zlentry_uid_include_list_map).unwrap();
        // set up defaults of a zero'd array
        let mut zeroed_array: [u32; UID_COUNT] = [0; UID_COUNT];

        if include_uid_bool {
            for (uid_list_counter, value) in only_these_uids_vec.iter().enumerate() {
                zeroed_array[uid_list_counter] = *value;
            }
            debug!("array of specific uids to watch: {:?}", zeroed_array);
        }

        // add the data to the map by index / the values will be retrieved by index in ebpf-land
        zlentry_uid_list_map.insert(0, zeroed_array, 0)?;

        // Process events from the ring buffer
        let ring_buf = RingBuf::try_from(ebpf.take_map("zlentry_events").ok_or_else(|| {
            format!(
                "eBPF map '{}' not found in loaded object - binary/eBPF build mismatch?",
                "zlentry_events"
            )
        })?)?;
        let async_fd = AsyncFd::with_interest(ring_buf, Interest::READABLE)?;

        let ref_executable_vec: Vec<String> = canonical_executable_vec.clone();
        let ref_global_url = global_url.clone();
        let ref_syslog_address = syslog_address.clone();
        let client = Client::new();
        let ref_hostname = hostname.clone();

        // now spawn the async stuff
        tokio::task::spawn(async move {
            consume_shell_ebpf_map(
                &client,
                async_fd,
                ref_executable_vec,
                ref_global_url,
                http_bool,
                ref_syslog_address,
                ref_hostname,
                syslog_bool,
                args.json,
                args.debug,
            )
            .await;
        });
    }
    if should_run_default_execve_monitor(
        args.syscall_execve,
        args.bash,
        args.zsh,
        args.memory_faults.is_some(),
        args.socket,
        args.memory,
        args.cpu,
        args.gpu,
        args.io,
        args.syscalls.is_some(),
    ) {
        // this is the main program functionality
        // the default option if the other shells are not selected
        // load the ebpf program
        let program2: &mut TracePoint = ebpf
            .program_mut("panhandle")
            .unwrap()
            .try_into()
            .inspect_err(|e| error!("failed to load eBPF program 'panhandle': {}", e))?;
        program2
            .load()
            .inspect_err(|e| error!("failed to load tracepoint 'sys_enter_execve': {}", e))?;
        program2
            .attach("syscalls", "sys_enter_execve")
            .inspect_err(|e| error!("failed to attach tracepoint 'sys_enter_execve': {}", e))?;
        debug!("attached eBPF tracepoint 'syscalls:sys_enter_execve'");

        // get the uid_options map from ebpf land
        let uid_options_map = ebpf.take_map("uid_options").ok_or_else(|| {
            format!(
                "eBPF map '{}' not found in loaded object - binary/eBPF build mismatch?",
                "uid_options"
            )
        })?;
        let mut program_options: HashMap<_, u32, u32> = HashMap::try_from(uid_options_map).unwrap();
        // add the data as u32s to the map by index / the values will be retrieved by index in ebpf-land so the index is hard-coded
        // this is the shells identifier
        program_options.insert(UID_OPT_SHELLS, args.shells as u32, 0)?;
        // this is the min uid identifier
        program_options.insert(
            UID_OPT_EXCLUDE_MIN,
            args.exclude_min_uid.unwrap_or(MINUID),
            0,
        )?;
        // this is the max uid identifier
        program_options.insert(
            UID_OPT_EXCLUDE_MAX,
            args.exclude_max_uid.unwrap_or(MAXUID),
            0,
        )?;
        // this is the include uid list option identifier
        program_options.insert(UID_OPT_INCLUDE_ENABLED, include_uid_bool as u32, 0)?;

        // get the uid_include_list map from ebpf land
        let uid_include_list_map = ebpf.take_map("uid_include_list").ok_or_else(|| {
            format!(
                "eBPF map '{}' not found in loaded object - binary/eBPF build mismatch?",
                "uid_include_list"
            )
        })?;
        let mut uid_list_map: HashMap<_, u32, [u32; UID_COUNT]> =
            HashMap::try_from(uid_include_list_map).unwrap();
        // set up defaults of a zero'd array
        let mut zeroed_array: [u32; UID_COUNT] = [0; UID_COUNT];

        if include_uid_bool {
            for (uid_list_counter, value) in only_these_uids_vec.iter().enumerate() {
                zeroed_array[uid_list_counter] = *value;
            }
            debug!("array of specific uids to watch: {:?}", zeroed_array);
        }

        // add the data to the map by index / the values will be retrieved by index in ebpf-land
        uid_list_map.insert(0, zeroed_array, 0)?;

        // Process events from the ring buffer
        let ring_buf =
            RingBuf::try_from(ebpf.take_map("panhandle_execve_events").ok_or_else(|| {
                format!(
                    "eBPF map '{}' not found in loaded object - binary/eBPF build mismatch?",
                    "panhandle_execve_events"
                )
            })?)?;
        let async_fd = AsyncFd::with_interest(ring_buf, Interest::READABLE)?;

        let ref_executable_vec: Vec<String> = canonical_executable_vec.clone();
        let ref_global_url = global_url.clone();
        let ref_syslog_address = syslog_address.clone();
        let client = Client::new();
        let ref_hostname = hostname.clone();

        // now spawn the async stuff
        tokio::task::spawn(async move {
            consume_execve_ebpf_map(
                &client,
                async_fd,
                ref_executable_vec,
                ref_global_url,
                http_bool,
                ref_syslog_address,
                ref_hostname,
                syslog_bool,
                args.json,
                args.debug,
            )
            .await;
        });
    }
    debug!("monitoring for events in ebpf-land...");
    // await the escape signal - this may need to change based on the method of running the program
    signal::ctrl_c().await?;
    debug!("cleanly exiting program as requested");
    if let Some(handle_ref) = memory_fault_handle {
        handle_ref.abort();
    };
    if let Some(handle_ref) = memory_usage_handle {
        handle_ref.abort();
    };
    if let Some(handle_ref) = socket_handle {
        handle_ref.abort();
    }
    if let Some(handle_ref) = io_handle {
        handle_ref.abort();
    }
    if let Some(handle_ref) = cpu_handle {
        handle_ref.abort();
    }
    if let Some(handle_ref) = gpu_handle {
        handle_ref.abort();
    }
    Ok(())
}
