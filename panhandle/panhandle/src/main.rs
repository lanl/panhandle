use std::{
    fs::{File, canonicalize},
    panic,
    path::PathBuf,
    process,
    sync::{Arc, Mutex},
};

use clap::Parser;
use machine_info::Machine;
use panhandle::{
    blocking,
    config::{AppConfig, PanhandleConfig, ShellConfig},
    ebpf_loader, helpers, input_configs, monitor_cpu_usage, monitor_gpu_usage, monitor_io_usage,
    monitor_network_usage, procfs_helpers,
};
use reqwest::Client;
use simplelog::*;
use tokio::{
    signal,
    task::JoinHandle,
    time::{Duration, sleep},
};
use uzers::get_current_uid;

// monitor_process_bounds and unit_tests have no library-crate equivalent (the former
// is bin-only, the latter is this binary's own test module), so they stay as local
// modules; everything else above comes from the panhandle library crate instead of a
// second, separately-compiled local copy of the same file.
#[rustfmt::skip]
mod monitor_process_bounds;
mod unit_tests;
// Use explicit imports to avoid conflicts with panhandle_common
use helpers::{
    consume_execve_ebpf_map, consume_shell_ebpf_map, consume_socket_stats_ebpf_map,
    get_canonical_executable_list, resolve_comm_list_mode, validate_count, validate_syslog,
    validate_url,
};
use input_configs::*;
use monitor_cpu_usage::*;
use monitor_gpu_usage::*;
use monitor_io_usage::*;
use monitor_network_usage::*;
use monitor_process_bounds::*;
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

    // replace the standard backtrace message with a one-line logged error if not debug,
    // so a panicking monitor task still shows up in the configured log outputs
    if !args.debug {
        panic::set_hook(Box::new(|info| {
            error!("internal error, a monitor stopped: {}", info);
        }));
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
                    Some(addr) => Arc::new(addr), // --syslog unix or --syslog /dev/log
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

    let mut uid_include_array: [u32; UID_COUNT] = [0; UID_COUNT];
    if include_uid_bool {
        for (i, value) in only_these_uids_vec.iter().enumerate() {
            uid_include_array[i] = *value;
        }
        debug!("array of specific uids to watch: {:?}", uid_include_array);
    }

    // the execve program and the readline/zlentry programs each get their own UID
    // filter maps (populated below by ebpf_loader::load_ebpf), but today they're
    // always configured identically from the same CLI/config-file flags
    let panhandle_uid_config = PanhandleConfig {
        shells: args.shells as u32,
        exclude_min_uid: args.exclude_min_uid.unwrap_or(MINUID),
        exclude_max_uid: args.exclude_max_uid.unwrap_or(MAXUID),
        include_enabled: include_uid_bool as u32,
        include_uids: uid_include_array,
    };
    let shell_uid_config = ShellConfig {
        shells: panhandle_uid_config.shells,
        exclude_min_uid: panhandle_uid_config.exclude_min_uid,
        exclude_max_uid: panhandle_uid_config.exclude_max_uid,
        include_enabled: panhandle_uid_config.include_enabled,
        include_uids: panhandle_uid_config.include_uids,
    };

    // load the built ebpf program and populate the uid_options/uid_include_list maps
    // for the execve, readline, and zlentry programs
    // this looks like a failure until the ebpf build runs
    let loaded_ebpf = ebpf_loader::load_ebpf(args.debug, &panhandle_uid_config, &shell_uid_config)?;
    let mut ebpf = loaded_ebpf.ebpf;
    let shared_btf = loaded_ebpf.btf;

    // polling frequency variable for performance monitoring tasks
    let mut polling_freq_seconds: u32 = 30; // default interval is 30 seconds; if changed, be sure to reflect the change in input_config.rs
    if let Some(poll) = args.poll {
        polling_freq_seconds = poll;
    }

    // One-line summary of what's about to start, so a user staring at a wall of
    // startup debug noise (eBPF relocation, verifier output, etc.) can tell at a
    // glance what's actually active without reconstructing it from the args dump.
    {
        let mut enabled: Vec<String> = Vec::new();
        if args.cpu {
            enabled.push("cpu".to_string());
        }
        if args.gpu {
            enabled.push("gpu".to_string());
        }
        if args.io {
            enabled.push("io".to_string());
        }
        if args.memory {
            enabled.push("memory".to_string());
        }
        if let Some(threshold) = args.memory_faults {
            enabled.push(format!("memory-faults(threshold={})", threshold));
        }
        if args.socket {
            enabled.push("socket".to_string());
        }
        if args.bound {
            enabled.push("bound".to_string());
        }
        if args.bash {
            enabled.push("bash".to_string());
        }
        if args.zsh {
            enabled.push("zsh".to_string());
        }
        if let Some(syscalls) = &args.syscalls {
            enabled.push(format!("syscalls({})", syscalls.join(",")));
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
            args.bound,
            args.syscalls.is_some(),
        ) {
            enabled.push("execve".to_string());
        }

        let pid_filter_desc = args
            .pid_list
            .as_ref()
            .map(|pids| format!(", pid_filter={:?}", pids))
            .unwrap_or_default();
        debug!(
            "enabled: [{}]{}, poll={}s",
            enabled.join(", "),
            pid_filter_desc,
            polling_freq_seconds
        );
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
        let btf = shared_btf
            .as_ref()
            .ok_or("BTF not available on this system - socket monitoring requires it")?;

        // Attach all network monitoring programs
        ebpf_loader::attach_btf_tracepoint(
            &mut ebpf,
            "inet_sock_set_state",
            "inet_sock_set_state",
            btf,
        )?;
        debug!("attached eBPF BTF tracepoint 'inet_sock_set_state'");

        // Attach fentry/fexit for data transfer tracking - fexit is required for
        // tcp_sendmsg/udp_sendmsg/udp_recvmsg, which need the real return value (see
        // socket.rs); tcp_cleanup_rbuf only needs fentry since its argument is already
        // accurate at entry.
        ebpf_loader::attach_fexit(&mut ebpf, "tcp_sendmsg", "tcp_sendmsg", btf)?;
        ebpf_loader::attach_fentry(&mut ebpf, "tcp_cleanup_rbuf", "tcp_cleanup_rbuf", btf)?;
        ebpf_loader::attach_fexit(&mut ebpf, "udp_sendmsg", "udp_sendmsg", btf)?;
        ebpf_loader::attach_fexit(&mut ebpf, "udp_recvmsg", "udp_recvmsg", btf)?;

        // Socket probes stream per-event deltas over a ring buffer rather than
        // maintaining shared aggregate state on the kernel side (see socket.rs for
        // why); this userspace-owned map accumulates them, and monitor_network_usage
        // both reads and prunes it.
        let net_stats: SharedNetStats =
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

        let socket_async_fd = ebpf_loader::create_ring_buffer_async_fd(&mut ebpf, "socket_events")?;
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
        let pid_filter = args.pid_list.clone();

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
                    &pid_filter,
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

    // set up process bound monitoring
    let mut bound_handle: Option<JoinHandle<()>> = None;
    if args.bound {
        let btf = shared_btf
            .as_ref()
            .ok_or("BTF not available on this system - process-bound monitoring requires it")?;

        ebpf_loader::attach_fentry(&mut ebpf, "tcp_recvmsg_entry", "tcp_recvmsg", btf)?;
        debug!("attached eBPF fentry 'tcp_recvmsg_entry' -> tcp_recvmsg");

        // Attach fexit on return from tcp_recvmsg to compute elapsed wait time and
        // fold it into NET_WAIT.
        ebpf_loader::attach_fexit(&mut ebpf, "tcp_recvmsg_exit", "tcp_recvmsg", btf)?;
        debug!("attached eBPF fexit 'tcp_recvmsg_exit' -> tcp_recvmsg");

        // Same timing pair for UDP, folding into the same NET_WAIT entry per process -
        // "Network_Wait" is meant to cover time spent waiting on any socket read.
        ebpf_loader::attach_fentry(&mut ebpf, "udp_recvmsg_entry", "udp_recvmsg", btf)?;
        debug!("attached eBPF fentry 'udp_recvmsg_entry' -> udp_recvmsg");

        ebpf_loader::attach_fexit(&mut ebpf, "udp_recvmsg_exit", "udp_recvmsg", btf)?;
        debug!("attached eBPF fexit 'udp_recvmsg_exit' -> udp_recvmsg");

        // Network-wait probes stream per-event deltas over a ring buffer rather than
        // maintaining shared aggregate state on the kernel side (see network_bound.rs
        // for why); this userspace-owned map accumulates them, and
        // monitor_process_bounds both reads and prunes it.
        let net_wait: SharedNetWaitMap = Arc::new(Mutex::new(std::collections::HashMap::new()));

        let net_wait_async_fd =
            ebpf_loader::create_ring_buffer_async_fd(&mut ebpf, "net_wait_events")?;
        let net_wait_consumer = net_wait.clone();
        tokio::task::spawn(consume_net_wait_ebpf_map(
            net_wait_async_fd,
            net_wait_consumer,
        ));

        let url = global_url.clone();
        let host = hostname.clone();
        let syslog = syslog_address.clone();
        let verbose_mode = args.verbose;
        let client = Client::new();
        let net_wait_for_task = net_wait;

        bound_handle = Some(tokio::task::spawn(async move {
            loop {
                monitor_process_bounds(
                    &args.json,
                    &http_bool,
                    &syslog_bool,
                    &verbose_mode,
                    &host,
                    &url,
                    &syslog,
                    &client,
                    &args.debug,
                    &net_wait_for_task,
                )
                .await;
                let _ = sleep(Duration::from_secs(polling_freq_seconds.into())).await;
            }
        }))
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

        let blocking_config = AppConfig {
            comm_allow: args.comm_allow.clone().unwrap_or_default(),
            comm_deny: args.comm_deny.clone().unwrap_or_default(),
            block_paths: args.block_paths.clone().unwrap_or_default(),
            syscalls: syscalls.clone(),
            cgroup_path: args.cgroup.clone(),
            ..Default::default()
        };

        if blocking_config.block_paths.is_empty() && args.verbose {
            println!(
                "Process blocking was turned on but no filepath list was provided. Defaulting to blocking all paths."
            );
        }

        let btf = shared_btf
            .as_ref()
            .ok_or("BTF not available on this system - syscall blocking requires it")?;
        blocking::setup_syscall_blocking(&mut ebpf, &blocking_config, btf)?;
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

        // readline stuff; the uid_options/uid_include_list maps for this program were
        // already populated by ebpf_loader::load_ebpf above
        ebpf_loader::attach_uprobe(
            &mut ebpf,
            "readline",
            "readline_internal_teardown",
            &file_string,
        )?;
        debug!("attached eBPF uprobe 'readline' to '{}'", file_string);

        // Process events from the ring buffer
        let async_fd = ebpf_loader::create_ring_buffer_async_fd(&mut ebpf, "readline_events")?;

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

        // zlentry stuff; the uid_options/uid_include_list maps for this program were
        // already populated by ebpf_loader::load_ebpf above
        ebpf_loader::attach_uprobe(&mut ebpf, "zlentry", "zleentry", &file_string)?;
        debug!("attached eBPF uprobe 'zlentry' to '{}'", file_string);

        // Process events from the ring buffer
        let async_fd = ebpf_loader::create_ring_buffer_async_fd(&mut ebpf, "zlentry_events")?;

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
        args.bound,
        args.syscalls.is_some(),
    ) {
        // this is the main program functionality
        // the default option if the other shells are not selected
        // load the ebpf program; the uid_options/uid_include_list maps for this
        // program were already populated by ebpf_loader::load_ebpf above
        ebpf_loader::attach_tracepoint(&mut ebpf, "panhandle", "syscalls", "sys_enter_execve")?;
        debug!("attached eBPF tracepoint 'syscalls:sys_enter_execve'");

        // Process events from the ring buffer
        let async_fd =
            ebpf_loader::create_ring_buffer_async_fd(&mut ebpf, "panhandle_execve_events")?;

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
    if let Some(handle_ref) = bound_handle {
        handle_ref.abort();
    }
    Ok(())
}
