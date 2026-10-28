use std::{process, sync::Arc};

use clap::Parser;
use reqwest::Client;
use simplelog::*;
use tokio::{
    io::{Interest, unix::AsyncFd},
    signal,
};
use uzers::get_current_uid;

mod blocking;
mod config;
mod ebpf_loader;
mod error;
mod helpers;
mod input_configs;
mod monitor_cpu_usage;
mod monitor_gpu_usage;
mod monitor_io_usage;
mod monitor_network_usage;
mod monitors;
mod output;
mod procfs_helpers;
mod shell;
mod unit_tests;

use blocking::setup_syscall_blocking;
use config::AppConfig;
use ebpf_loader::{
    attach_btf_tracepoint, attach_kprobe, attach_raw_tracepoint, create_ring_buffer_async_fd,
    load_ebpf,
};
use error::{PanhandleError, Result};
use helpers::*;
use input_configs::{ConfigArgs, RawArgs};
use monitors::{
    MonitorContext, run_cpu_monitor, run_gpu_monitor, run_io_monitor, run_memory_faults_monitor,
    run_memory_monitor, run_network_monitor,
};
use output::OutputConfig;
use panhandle_common::{EXECUTABLE_COUNT, MAX_COMM_LENGTH, MAX_PATH_LENGTH, MAXUID, MINUID};
use shell::{setup_bash_monitoring, setup_zsh_monitoring};

/// Validate every user-controlled numeric/list argument up front, before the
/// root-privilege check and eBPF load later in `main`. Doing this early means
/// startup fails fast on bad input (a typo'd config, an oversized list) without
/// first requiring root or a working eBPF-capable kernel - and it's what makes
/// these failure modes reachable by a plain subprocess integration test rather
/// than only by a root-gated one.
fn validate_args_or_exit(args: &RawArgs) {
    if let Some(poll) = args.poll
        && poll == 0
    {
        eprintln!("--poll must be at least 1 (got 0)");
        process::exit(1);
    }

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
    }

    if let Some(ref paths) = args.block_paths {
        for path in paths {
            if path.len() > MAX_PATH_LENGTH {
                eprintln!(
                    "--block-paths entry '{}' exceeds maximum length of {}",
                    path, MAX_PATH_LENGTH
                );
                process::exit(1);
            }
        }
    }

    for comm in args
        .comm_deny
        .iter()
        .flatten()
        .chain(args.comm_allow.iter().flatten())
    {
        if comm.len() > MAX_COMM_LENGTH {
            eprintln!(
                "--comm-deny/--comm-allow entry '{}' exceeds maximum length of {}",
                comm.as_str(),
                MAX_COMM_LENGTH
            );
            process::exit(1);
        }
    }

    if let Some(ref syscalls) = args.syscalls {
        for syscall in syscalls {
            if !["open", "openat", "creat", "execve"].contains(&syscall.as_str()) {
                eprintln!(
                    "Invalid syscall '{}': supported: open, openat, creat, execve",
                    syscall
                );
                process::exit(1);
            }
        }
    }

    if let Some(Some(ref syslog_addr)) = args.syslog
        && !syslog_addr.is_empty()
        && let Err(e) = tokio::runtime::Handle::current().block_on(validate_syslog(syslog_addr))
    {
        eprintln!("{}", e);
        process::exit(1);
    }

    if let Some(ref url) = args.http
        && let Err(e) = tokio::runtime::Handle::current().block_on(validate_url(url))
    {
        eprintln!("{}", e);
        process::exit(1);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = RawArgs::parse();
    validate_args_or_exit(&args);

    if args.debug {
        println!("Starting Panhandle with arguments: {:#?}", args);
    }

    // Handle --output-config flag
    if let Some(ref output_config_path) = args.output_config {
        let config = serde_saphyr::to_string(&args).map_err(PanhandleError::YamlSerialization)?;
        let path = std::path::Path::new(output_config_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, config)?;
        println!("Config written to {}", output_config_path.display());
        process::exit(0);
    }

    // Load and validate config file if provided (before root check so integration tests can validate config without root)
    let args = if let Some(config_path) = args.config.clone() {
        merge_args(args, &config_path).await?
    } else {
        args
    };

    // Build AppConfig from merged args
    let app_config = build_app_config(&args)?;

    // Validate all configuration
    app_config.validate_all()?;

    if let Err(e) = run_main(args, app_config).await {
        eprintln!("Error: {}", e);
        process::exit(1);
    }

    Ok(())
}

async fn run_main(args: RawArgs, app_config: AppConfig) -> Result<()> {
    // Check root privileges (skip in test mode for integration tests)
    let current_uid = get_current_uid();
    let test_mode = std::env::var("PANHANDLE_TEST_MODE").is_ok();
    if current_uid != 0 && !test_mode {
        return Err(PanhandleError::PermissionDenied(
            "Panhandle must run as root".to_string(),
        ));
    }

    // Setup logging
    let log_level = if args.debug {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    simplelog::TermLogger::init(
        log_level,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // Get hostname
    let hostname = Arc::new(
        hostname::get()
            .ok()
            .and_then(|os| os.into_string().ok())
            .unwrap_or_else(|| "UNKNOWN_HOST".to_string()),
    );

    // Setup HTTP client
    let client = Client::new();

    // Setup output configuration
    let http_enabled = args.http.is_some();
    let syslog_enabled = args.syslog.is_some();
    let syslog_address = args
        .syslog
        .as_ref()
        .and_then(|s| s.clone())
        .unwrap_or_else(|| "udp://127.0.0.1:514".to_string());
    let http_url = args
        .http
        .clone()
        .unwrap_or_else(|| "http://127.0.0.1:8080/events".to_string());

    let output_config = OutputConfig::new(
        hostname.clone(),
        args.json,
        http_enabled,
        syslog_enabled,
        Arc::new(syslog_address),
        Arc::new(http_url),
        args.debug,
        client.clone(),
    )?;

    // Build GlobalData configs
    let (panhandle_config, shell_config) = app_config.build_global_configs();

    // Load eBPF program
    let mut loaded_ebpf = load_ebpf(args.debug, &panhandle_config, &shell_config)?;

    // Create monitor context
    let monitor_ctx = MonitorContext::new(app_config.clone(), output_config.clone());

    // Setup various monitors
    let mut handles = Vec::new();

    // CPU monitoring
    if args.cpu {
        let ctx = MonitorContext::new(app_config.clone(), output_config.clone());
        handles.push(tokio::spawn(run_cpu_monitor(ctx)));
    }

    // GPU monitoring
    if args.gpu {
        let ctx = MonitorContext::new(app_config.clone(), output_config.clone());
        handles.push(tokio::spawn(run_gpu_monitor(ctx)));
    }

    // Network monitoring
    if args.socket {
        if let Some(ref btf) = loaded_ebpf.btf {
            attach_btf_tracepoint(
                &mut loaded_ebpf.ebpf,
                "inet_sock_set_state",
                "inet_sock_set_state",
                btf,
            )?;
            attach_kprobe(&mut loaded_ebpf.ebpf, "tcp_sendmsg")?;
            attach_kprobe(&mut loaded_ebpf.ebpf, "tcp_cleanup_rbuf")?;
            attach_kprobe(&mut loaded_ebpf.ebpf, "udp_sendmsg")?;
            attach_kprobe(&mut loaded_ebpf.ebpf, "udp_recvmsg")?;
        }

        let net_stats = monitor_ctx.net_stats.clone();
        let async_fd = create_ring_buffer_async_fd(&mut loaded_ebpf.ebpf, "socket_events")?;

        let ctx = MonitorContext::new(app_config.clone(), output_config.clone());
        handles.push(tokio::spawn(run_network_monitor(ctx)));

        // Spawn socket stats consumer
        handles.push(tokio::spawn(consume_socket_stats(async_fd, net_stats)));
    }

    // IO monitoring
    if args.io {
        let ctx = MonitorContext::new(app_config.clone(), output_config.clone());
        handles.push(tokio::spawn(run_io_monitor(ctx)));
    }

    // Memory faults monitoring
    if args.memory_faults.is_some() {
        let ctx = MonitorContext::new(app_config.clone(), output_config.clone());
        handles.push(tokio::spawn(run_memory_faults_monitor(ctx)));
    }

    // Memory usage monitoring
    if args.memory {
        let ctx = MonitorContext::new(app_config.clone(), output_config.clone());
        handles.push(tokio::spawn(run_memory_monitor(ctx)));
    }

    // Syscall blocking
    if args.syscalls.is_some() {
        if let Some(ref btf) = loaded_ebpf.btf {
            setup_syscall_blocking(&mut loaded_ebpf.ebpf, &app_config, btf)?;
        } else {
            eprintln!("Warning: BTF not available, syscall blocking disabled");
        }
    }

    // Bash monitoring
    if args.bash {
        setup_bash_monitoring(&mut loaded_ebpf, &app_config, &output_config).await?;
    }

    // Zsh monitoring
    if args.zsh {
        setup_zsh_monitoring(&mut loaded_ebpf, &app_config, &output_config).await?;
    }

    // Default execve monitoring
    if app_config.should_run_execve_monitor() {
        attach_raw_tracepoint(&mut loaded_ebpf.ebpf, "panhandle", "sys_enter_execve")?;

        let async_fd =
            create_ring_buffer_async_fd(&mut loaded_ebpf.ebpf, "panhandle_execve_events")?;

        let executables = app_config.executables.clone();
        let client = output_config.client.clone();
        let hostname = output_config.hostname.clone();
        let json = output_config.json;
        let http = output_config.http;
        let syslog = output_config.syslog;
        let syslog_address = output_config.syslog_address.clone();
        let http_url = output_config.http_url.clone();
        let debug = output_config.debug;

        handles.push(tokio::spawn(async move {
            consume_execve_events(
                client,
                async_fd,
                executables,
                hostname,
                json,
                http,
                syslog,
                syslog_address,
                http_url,
                debug,
            )
            .await
        }));
    }

    // Wait for shutdown signal
    signal::ctrl_c().await?;
    info!("Shutting down...");

    // Abort all monitor tasks
    for handle in handles {
        handle.abort();
    }

    Ok(())
}

/// Build AppConfig from CLI args
fn build_app_config(args: &RawArgs) -> Result<AppConfig> {
    let include_uids: Vec<u32> = if let Some(ref uids) = args.include_uid {
        let mut parsed = Vec::new();
        for uid_str in uids {
            match uid_str.parse::<u32>() {
                Ok(uid) => parsed.push(uid),
                Err(_) => {
                    return Err(PanhandleError::UidValidation(format!(
                        "Invalid --include-uid value '{}': must be a non-negative integer",
                        uid_str
                    )));
                }
            }
        }
        parsed
    } else {
        Vec::new()
    };

    Ok(AppConfig {
        shells: args.shells,
        exclude_min_uid: args.exclude_min_uid.unwrap_or(MINUID),
        exclude_max_uid: args.exclude_max_uid.unwrap_or(MAXUID),
        include_uids,
        executables: args.executables.clone().unwrap_or_default(),
        block_paths: args.block_paths.clone().unwrap_or_default(),
        comm_allow: args.comm_allow.clone().unwrap_or_default(),
        comm_deny: args.comm_deny.clone().unwrap_or_default(),
        syscalls: args.syscalls.clone().unwrap_or_default(),
        pid_list: args.pid_list.clone().unwrap_or_default(),
        poll_seconds: args.poll.unwrap_or(30),
        debug: args.debug,
        verbose: args.verbose,
        json: args.json,
        http: args.http.is_some(),
        syslog: args.syslog.is_some(),
        syslog_address: args
            .syslog
            .clone()
            .flatten()
            .unwrap_or_else(|| "udp://127.0.0.1:514".to_string()),
        http_url: args
            .http
            .clone()
            .unwrap_or_else(|| "http://127.0.0.1:8080/events".to_string()),
        bash: args.bash,
        zsh: args.zsh,
        cpu: args.cpu,
        gpu: args.gpu,
        network: args.socket,
        io: args.io,
        memory: args.memory,
        memory_faults: args.memory_faults,
        execve: args.execve,
    })
}

/// Merge CLI args with config file
async fn merge_args(mut args: RawArgs, config_path: &str) -> Result<RawArgs> {
    let path_ref = std::path::Path::new(config_path);
    let config_str = std::fs::read_to_string(config_path)?;

    // Check file extension first
    match path_ref.extension().and_then(|e| e.to_str()) {
        Some("json") => {
            // First parse as ConfigArgs to validate unknown fields
            let _config_args: ConfigArgs = serde_json::from_str(&config_str)?;
            // Then parse as RawArgs for merging
            let file_args: RawArgs = serde_json::from_str(&config_str)?;
            merge_raw_args(&mut args, file_args);
        }
        Some("yaml") | Some("yml") => {
            // First parse as ConfigArgs to validate unknown fields
            let _config_args: ConfigArgs = serde_saphyr::from_str(&config_str)?;
            // Then parse as RawArgs for merging
            let file_args: RawArgs = serde_saphyr::from_str(&config_str)?;
            merge_raw_args(&mut args, file_args);
        }
        other => {
            return Err(PanhandleError::InvalidArgument(format!(
                "Unsupported config type {:?}",
                other
            )));
        }
    }

    Ok(args)
}

/// Helper to merge RawArgs from config file into CLI args
fn merge_raw_args(args: &mut RawArgs, file_args: RawArgs) {
    // Config file values are overridden by CLI args (which are already in `args`)
    if args.executables.is_none() {
        args.executables = file_args.executables;
    }
    if args.exclude_min_uid.is_none() {
        args.exclude_min_uid = file_args.exclude_min_uid;
    }
    if args.exclude_max_uid.is_none() {
        args.exclude_max_uid = file_args.exclude_max_uid;
    }
    if args.include_uid.is_none() {
        args.include_uid = file_args.include_uid;
    }
    if args.block_paths.is_none() {
        args.block_paths = file_args.block_paths;
    }
    if args.comm_allow.is_none() {
        args.comm_allow = file_args.comm_allow;
    }
    if args.comm_deny.is_none() {
        args.comm_deny = file_args.comm_deny;
    }
    if args.syscalls.is_none() {
        args.syscalls = file_args.syscalls;
    }
    if args.pid_list.is_none() {
        args.pid_list = file_args.pid_list;
    }
    if args.poll.is_none() {
        args.poll = file_args.poll;
    }
    if !args.debug {
        args.debug = file_args.debug;
    }
    if !args.verbose {
        args.verbose = file_args.verbose;
    }
    if !args.json {
        args.json = file_args.json;
    }
    if args.http.is_none() {
        args.http = file_args.http;
    }
    if args.syslog.is_none() {
        args.syslog = file_args.syslog;
    }
    if !args.bash {
        args.bash = file_args.bash;
    }
    if !args.zsh {
        args.zsh = file_args.zsh;
    }
    if !args.cpu {
        args.cpu = file_args.cpu;
    }
    if !args.gpu {
        args.gpu = file_args.gpu;
    }
    if !args.socket {
        args.socket = file_args.socket;
    }
    if !args.io {
        args.io = file_args.io;
    }
    if !args.memory {
        args.memory = file_args.memory;
    }
    if args.memory_faults.is_none() {
        args.memory_faults = file_args.memory_faults;
    }
    if !args.execve {
        args.execve = file_args.execve;
    }
    if !args.shells {
        args.shells = file_args.shells;
    }
}

/// Consume execve events from ring buffer
async fn consume_execve_events(
    client: Client,
    mut async_fd: AsyncFd<aya::maps::RingBuf<aya::maps::MapData>>,
    executable_vec: Vec<String>,
    hostname: Arc<String>,
    json: bool,
    http: bool,
    syslog: bool,
    syslog_address: Arc<String>,
    http_url: Arc<String>,
    debug: bool,
) -> Result<()> {
    use crate::output::OutputConfig;
    use panhandle_common::ExecveEvent;

    let output = OutputConfig::new(
        hostname,
        json,
        http,
        syslog,
        syslog_address,
        http_url,
        debug,
        client,
    )?;

    loop {
        let Ok(mut guard) = async_fd.ready_mut(Interest::READABLE).await else {
            continue;
        };
        let mut events = Vec::new();
        let ring_buf = guard.get_inner_mut();
        while let Some(item) = ring_buf.next() {
            if item.len() >= core::mem::size_of::<ExecveEvent>() {
                events.push(unsafe { read_ring_item::<ExecveEvent>(&item) });
            }
        }
        guard.clear_ready();

        for event in &events {
            if !event_matches_executable_filter(
                &executable_vec,
                std::str::from_utf8(&event.filename).unwrap_or_default(),
            ) {
                continue;
            }

            let json_payload = output.format_execve_event_json(event, "execve");
            let text_payload = output.format_execve_event_text(event, "execve");
            output.output_event(&json_payload, &text_payload).await?;
        }
    }
}

/// Consume socket stats events
async fn consume_socket_stats(
    mut async_fd: AsyncFd<aya::maps::RingBuf<aya::maps::MapData>>,
    net_stats: monitors::SharedNetStats,
) -> Result<()> {
    use panhandle_common::SocketStatsEvent;

    loop {
        let Ok(mut guard) = async_fd.ready_mut(Interest::READABLE).await else {
            continue;
        };
        let mut events = Vec::new();
        let ring_buf = guard.get_inner_mut();
        while let Some(item) = ring_buf.next() {
            if item.len() >= core::mem::size_of::<SocketStatsEvent>() {
                events.push(unsafe { read_ring_item::<SocketStatsEvent>(&item) });
            }
        }
        guard.clear_ready();

        for event in &events {
            // Apply socket stats event to shared net_stats
            let mut map = net_stats.lock().await;
            let entry = map.entry(event.pid).or_default();
            entry.tcp_established = entry
                .tcp_established
                .saturating_add_signed(event.tcp_established_delta);
            entry.tcp_syn_recv = entry
                .tcp_syn_recv
                .saturating_add_signed(event.tcp_syn_recv_delta);
            entry.tcp_close_wait = entry
                .tcp_close_wait
                .saturating_add_signed(event.tcp_close_wait_delta);
            entry.tcp_time_wait = entry
                .tcp_time_wait
                .saturating_add_signed(event.tcp_time_wait_delta);
            entry.tcp_fin_wait = entry
                .tcp_fin_wait
                .saturating_add_signed(event.tcp_fin_wait_delta);
            if event.udp_sockets_set != 0 {
                entry.udp_sockets = entry.udp_sockets.max(1);
            }
            entry.bytes_sent += event.bytes_sent_delta;
            entry.bytes_recv += event.bytes_recv_delta;
            entry.packets_sent += event.packets_sent_delta;
            entry.packets_recv += event.packets_recv_delta;
        }
    }
}
