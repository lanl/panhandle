use aya::{
    maps::{HashMap, PerCpuArray, perf::AsyncPerfEventArray},
    programs::{TracePoint, UProbe},
    util::online_cpus,
};
use aya_log::EbpfLogger;
use clap::Parser;
use std::{convert::TryInto, path::PathBuf};
use tokio::signal;
extern crate simplelog;
use bytes::BytesMut;
use file_matcher::FileNamed;

use reqwest::Client;
use simplelog::*;
use std::{
    fs::{File, canonicalize},
    panic, process,
    sync::Arc,
};
use uzers::get_current_uid;
#[rustfmt::skip]
// this is the local import section
mod helpers;
mod unit_tests;
use helpers::*;
use panhandle_common::*;
mod input_configs;
use crate::input_configs::*;

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
    // remove standard backtrace message if not debug
    if !args.debug {
        panic::set_hook(Box::new(|_| {}));
    }

    // Bump the memlock rlimit. This is needed for older kernels that don't use the new memcg
    // based accounting
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

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
                    println!("log file: {}", &path.display());
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

    // set up ebpf memory lock
    // SAFETY: unsafe call recommended by the Aya library, requires libc which is a dependency of the rpm build already
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // load the built ebpf program
    // this looks like a falure until the ebpf build runs
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/panhandle"
    )))?;

    // set up executable vars
    let mut canonical_executable_vec = Vec::new();
    if let Some(executables) = args.executables {
        canonical_executable_vec.append(&mut get_canonical_executable_list(&executables));
        if canonical_executable_vec.len() > EXECUTABLE_COUNT {
            info!("The number of executables requested to monitor exceeds the maximum");
            process::exit(1);
        };
    };

    // set up include uids
    let include_uid_bool = args.include_uid.is_some();
    let only_these_uids_vec: Vec<u32> = match args.include_uid {
        Some(inc) => inc
            .iter()
            .map(|uid_string| uid_string.parse::<u32>().unwrap())
            .collect(),
        None => Vec::new(),
    };

    if only_these_uids_vec.len() > UID_COUNT {
        info!(
            "The number of UIDs requested to monitor exceeds the maximum of {:}",
            UID_COUNT
        );
        process::exit(1);
    }

    // CPU monitoring
    if args.cpu {
        info!("Starting CPU usage monitoring...");

        // Load and attach the sched_switch tracepoint
        let program: &mut TracePoint = ebpf.program_mut("sched_switch").unwrap().try_into()?;
        program.load()?;
        program.attach("sched", "sched_switch")?;
        // EbpfLogger::init(&mut ebpf)?; // enables log messages on ebpf side

        info!("CPU monitoring eBPF program loaded and attached");

        // Get the per pid and busy cpu time hashmaps
        let pid_cpu_time_map = ebpf.take_map("per_cpu_time").unwrap();
        let pid_cpu_time = HashMap::try_from(pid_cpu_time_map)?;

        let busy_cpu_time_map = ebpf.take_map("busy_cpu_time").unwrap();
        let busy_cpu_time = PerCpuArray::try_from(busy_cpu_time_map)?;

        let pid_filter = args.pid_list.clone();
        let json_output = args.json;
        let debug_mode = args.debug;

        // Spawn CPU monitoring task
        tokio::spawn(async move {
            if let Err(e) = monitor_cpu_usage(
                pid_cpu_time,
                busy_cpu_time,
                pid_filter,
                json_output,
                debug_mode,
            )
            .await
            {
                error!("CPU monitoring error: {}", e);
            }
        });

        // Wait for Ctrl+C
        signal::ctrl_c().await?;
        info!("Shutting down CPU monitoring...");
        return Ok(());
    }

    // move to if statements for the main program args
    // goal is to try to allow a combination of all of the args
    // this introduces some code duplication
    if args.fmsh {
        // fmsh is a little weird - the best way that i have found to monitor it also includes bash
        // basically, find the libreadline shared library and look for it's teardown method...
        // in RedHat this is in the /lib64/ dir...
        // lets find this dir...
        let mut file: std::path::PathBuf = FileNamed::regex("libreadline.so.*")
            .within("/lib64/")
            .find()?;
        if !file.exists() {
            debug!("Could not find the libreadline shared library in /lib64/, looking in /lib/");
            file = FileNamed::regex("libreadline.so.*")
                .within("/lib/")
                .find()?;
            if !file.exists() {
                info!(
                    "Could not find the libreadline shared library in /lib64/ or /lib/, exiting with error"
                );
                process::exit(1);
            }
        }
        debug!("found file: {:?}", file);
        let file_string = file.into_os_string().into_string().unwrap();
        debug!(
            "converted PathBuf path to this file string: '{}'",
            file_string
        );

        // fmsh stuff
        let program: &mut UProbe = ebpf.program_mut("fmsh").unwrap().try_into()?;
        program.load()?;
        program.attach(
            Some("readline_internal_teardown"),
            0,
            file_string.as_str(),
            None,
        )?;

        // get the uid_options map from ebpf land
        let fmsh_uid_options_map = ebpf.take_map("fmsh_uid_options").unwrap();
        let mut program_options: HashMap<_, u32, u32> =
            HashMap::try_from(fmsh_uid_options_map).unwrap();
        // add the data as u32s to the map by index / the values will be retrieved by index in ebpf-land so the index is hard-coded
        // this is the shells identifier
        program_options.insert(0, args.shells as u32, 0)?;
        // this is the min uid identifier
        program_options.insert(1, args.exclude_min_uid.unwrap_or(MINUID), 0)?;
        // this is the max uid identifier
        program_options.insert(2, args.exclude_max_uid.unwrap_or(MAXUID), 0)?;
        // this is the include uid list option identifier
        program_options.insert(3, include_uid_bool as u32, 0)?;

        // get the uid_include_list map from ebpf land
        let fmsh_uid_include_list_map = ebpf.take_map("fmsh_uid_include_list").unwrap();
        let mut fmsh_uid_list_map: HashMap<_, u32, [u32; UID_COUNT]> =
            HashMap::try_from(fmsh_uid_include_list_map).unwrap();
        // set up defaults of a zero'd array
        let mut zeroed_array: [u32; UID_COUNT] = [0; UID_COUNT];

        if include_uid_bool {
            for (uid_list_counter, value) in only_these_uids_vec.iter().enumerate() {
                zeroed_array[uid_list_counter] = *value;
            }
            debug!("array of specific uids to watch: {:?}", zeroed_array);
        }
        // add the data to the map by index / the values will be retrieved by index in ebpf-land
        fmsh_uid_list_map.insert(0, zeroed_array, 0)?;

        let cpus: Vec<u32> = online_cpus().unwrap();
        let num_cpus: usize = cpus.len();

        // Process events from the perf buffer
        let mut events = AsyncPerfEventArray::try_from(ebpf.take_map("fmsh_events").unwrap())?;
        for cpu in cpus {
            let buf = events.open(cpu, Some(32))?;

            // have to clone these Vec's of Strings (due to lack of Copy trait) across the cpus for access to their data
            let ref_executable_vec: Vec<String> = canonical_executable_vec.clone();
            let ref_global_url = global_url.clone();
            let ref_syslog_address = syslog_address.clone();
            let client = Client::new();
            let ref_hostname = hostname.clone();

            // now spawn the async stuff
            tokio::task::spawn(async move {
                // note: if experiencing buffer overruns after changing default values the capacity here should be tweaked
                let buffers = (0..num_cpus)
                    .map(|_| BytesMut::with_capacity(2048))
                    .collect::<Vec<_>>();

                consume_shell_ebpf_map(
                    &client,
                    buf,
                    buffers,
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
    }
    if args.bash {
        // canonicalize the path and then convert to string
        let file: PathBuf = canonicalize("/bin/bash").unwrap_or_default();
        if !file.exists() {
            debug!("Could not find /bin/bash");
            process::exit(1);
        }
        debug!("found executable: {:?}", file);
        let file_string = file.into_os_string().into_string().unwrap();
        debug!(
            "converted PathBuf path to this file string: '{}'",
            file_string
        );

        // readline stuff
        let program: &mut UProbe = ebpf.program_mut("readline").unwrap().try_into()?;
        program.load()?;
        program.attach(Some("readline_internal_teardown"), 0, file_string, None)?;

        // get the uid_options map from ebpf land
        let readline_uid_options_map = ebpf.take_map("readline_uid_options").unwrap();
        let mut program_options: HashMap<_, u32, u32> =
            HashMap::try_from(readline_uid_options_map).unwrap();
        // add the data as u32s to the map by index / the values will be retrieved by index in ebpf-land so the index is hard-coded
        // this is the shells identifier
        program_options.insert(0, args.shells as u32, 0)?;
        // this is the min uid identifier
        program_options.insert(1, args.exclude_min_uid.unwrap_or(MINUID), 0)?;
        // this is the max uid identifier
        program_options.insert(2, args.exclude_max_uid.unwrap_or(MAXUID), 0)?;
        // this is the include uid list option identifier
        program_options.insert(3, include_uid_bool as u32, 0)?;

        // get the uid_include_list map from ebpf land
        let readline_uid_include_list_map = ebpf.take_map("readline_uid_include_list").unwrap();
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

        let cpus: Vec<u32> = online_cpus().unwrap();
        let num_cpus: usize = cpus.len();

        // Process events from the perf buffer
        let mut events = AsyncPerfEventArray::try_from(ebpf.take_map("readline_events").unwrap())?;
        for cpu in cpus {
            let buf = events.open(cpu, Some(32))?;

            // have to clone these Vec's of Strings (due to lack of Copy trait) across the cpus for access to their data
            let ref_executable_vec: Vec<String> = canonical_executable_vec.clone();
            let ref_global_url = global_url.clone();
            let ref_syslog_address = syslog_address.clone();
            let client = Client::new();
            let ref_hostname = hostname.clone();

            // now spawn the async stuff
            tokio::task::spawn(async move {
                // note: if experiencing buffer overruns after changing default values the capacity here should be tweaked
                let buffers = (0..num_cpus)
                    .map(|_| BytesMut::with_capacity(2048))
                    .collect::<Vec<_>>();

                consume_shell_ebpf_map(
                    &client,
                    buf,
                    buffers,
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
    }
    if args.zsh {
        // canonicalize the path and then convert to string
        let file: PathBuf = canonicalize("/bin/zsh").unwrap_or_default();
        if !file.exists() {
            debug!("Could not find /bin/zsh");
            process::exit(1);
        }
        debug!("found executable: {:?}", file);
        let file_string = file.into_os_string().into_string().unwrap();
        debug!(
            "converted PathBuf path to this file string: '{}'",
            file_string
        );

        // zlentry stuff
        let program: &mut UProbe = ebpf.program_mut("zlentry").unwrap().try_into()?;
        program.load()?;
        program.attach(Some("zleentry"), 0, file_string, None)?;

        // get the uid_options map from ebpf land
        let zlentry_uid_options_map = ebpf.take_map("zlentry_uid_options").unwrap();
        let mut program_options: HashMap<_, u32, u32> =
            HashMap::try_from(zlentry_uid_options_map).unwrap();
        // add the data as u32s to the map by index / the values will be retrieved by index in ebpf-land so the index is hard-coded
        // this is the shells identifier
        program_options.insert(0, args.shells as u32, 0)?;
        // this is the min uid identifier
        program_options.insert(1, args.exclude_min_uid.unwrap_or(MINUID), 0)?;
        // this is the max uid identifier
        program_options.insert(2, args.exclude_max_uid.unwrap_or(MAXUID), 0)?;
        // this is the include uid list option identifier
        program_options.insert(3, include_uid_bool as u32, 0)?;

        // get the uid_include_list map from ebpf land
        let zlentry_uid_include_list_map = ebpf.take_map("zlentry_uid_include_list").unwrap();
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

        let cpus = online_cpus().unwrap();
        let num_cpus = cpus.len();

        // Process events from the perf buffer
        let mut events = AsyncPerfEventArray::try_from(ebpf.take_map("zlentry_events").unwrap())?;
        for cpu in cpus {
            let buf = events.open(cpu, Some(32))?;

            // have to clone these Vec's of Strings (due to lack of Copy trait) across the cpus for access to their data
            let ref_executable_vec: Vec<String> = canonical_executable_vec.clone();
            let ref_global_url = global_url.clone();
            let ref_syslog_address = syslog_address.clone();
            let client = Client::new();
            let ref_hostname = hostname.clone();

            // now spawn the async stuff
            tokio::task::spawn(async move {
                // note: if experiencing buffer overruns after changing default values the capacity here should be tweaked
                let buffers = (0..num_cpus)
                    .map(|_| BytesMut::with_capacity(2048))
                    .collect::<Vec<_>>();

                consume_shell_ebpf_map(
                    &client,
                    buf,
                    buffers,
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
    }
    if args.syscall_execve || (!args.bash && !args.zsh && !args.fmsh) {
        // this is the main program functionality
        // the default option if the other shells are not selected
        // load the ebpf program
        let program2: &mut TracePoint = ebpf.program_mut("panhandle").unwrap().try_into()?;
        program2.load()?;
        program2.attach("syscalls", "sys_enter_execve")?;

        // get the uid_options map from ebpf land
        let uid_options_map = ebpf.take_map("uid_options").unwrap();
        let mut program_options: HashMap<_, u32, u32> = HashMap::try_from(uid_options_map).unwrap();
        // add the data as u32s to the map by index / the values will be retrieved by index in ebpf-land so the index is hard-coded
        // this is the shells identifier
        program_options.insert(0, args.shells as u32, 0)?;
        // this is the min uid identifier
        program_options.insert(1, args.exclude_min_uid.unwrap_or(MINUID), 0)?;
        // this is the max uid identifier
        program_options.insert(2, args.exclude_max_uid.unwrap_or(MAXUID), 0)?;
        // this is the include uid list option identifier
        program_options.insert(3, include_uid_bool as u32, 0)?;

        // get the uid_include_list map from ebpf land
        let uid_include_list_map = ebpf.take_map("uid_include_list").unwrap();
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

        let cpus: Vec<u32> = online_cpus().unwrap();
        let num_cpus = cpus.len();

        // Process events from the perf buffer
        let mut events =
            AsyncPerfEventArray::try_from(ebpf.take_map("panhandle_execve_events").unwrap())?;
        for cpu in cpus {
            let buf = events.open(cpu, Some(32))?;

            // have to clone these Vec's of Strings (due to lack of Copy trait) across the cpus for access to their data
            let ref_executable_vec: Vec<String> = canonical_executable_vec.clone();
            let ref_global_url = global_url.clone();
            let ref_syslog_address = syslog_address.clone();
            let client = Client::new();
            let ref_hostname = hostname.clone();

            // now spawn the async stuff
            tokio::task::spawn(async move {
                // note: if experiencing buffer overruns after changing default values the capacity here should be tweaked
                let buffers = (0..num_cpus)
                    .map(|_| BytesMut::with_capacity(2048))
                    .collect::<Vec<_>>();

                consume_execve_ebpf_map(
                    &client,
                    buf,
                    buffers,
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
    }
    debug!("monitoring for events in ebpf-land...");
    // await the escape signal - this may need to change based on the method of running the program
    signal::ctrl_c().await?;
    debug!("cleanly exiting program as requested");

    Ok(())
}
// cpu monitoring helper function
async fn monitor_cpu_usage(
    pid_cpu_time: HashMap<aya::maps::MapData, u32, u64>, // Map storing CPU time per process ID
    busy_cpu_time: PerCpuArray<aya::maps::MapData, u64>, // Array storing busy time per CPU core
    pid_filter: Option<Vec<u32>>, // Optional list of PIDs to monitor (None = monitor all/global)
    json_output: bool,            // Flag to control output format
    _debug_mode: bool,            // Debug mode flag (unused in this function)
) -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::HashMap as StdHashMap;

    // Create a timer that ticks every 1 second - this controls our monitoring frequency
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));

    // Get the number of online CPU cores on the system
    let num_cpus = online_cpus()
        .map_err(|(msg, err)| format!("{}: {}", msg, err))?
        .len();

    // Counter to track how many samples we've taken
    let mut sample_count = 0u64;

    // Print startup information banner (only if not using JSON output)
    if !json_output {
        info!("═══════════════════════════════════════════════════════════");
        info!("  CPU Usage Monitor Started");
        info!("  CPUs: {}", num_cpus);
        if let Some(ref pids) = pid_filter {
            info!("  Tracking PIDs: {:?}", pids);
        } else {
            info!("  Mode: Global CPU usage");
        }
        info!("═══════════════════════════════════════════════════════════");
    }

    // Variables to store previous measurements (needed to calculate deltas)
    let mut last_total_busy: u64 = 0; // Previous total busy CPU time across all cores
    let mut last_pid_times: StdHashMap<u32, u64> = StdHashMap::new(); // Previous CPU time per PID
    let mut pid_stats: StdHashMap<u32, PidStats> = StdHashMap::new(); // Accumulated statistics per PID

    // Structure to hold statistics for each monitored PID
    #[derive(Default)]
    struct PidStats {
        total_time: u64,      // Total cumulative CPU time
        sample_count: u64,    // Number of samples taken
        max_cpu_percent: f64, // Maximum CPU percentage observed
        avg_cpu_percent: f64, // Running average of CPU percentage
    }

    // Print table header (only if not using JSON output)
    if !json_output {
        println!(
            "\n{:<10} {:<12} {:<12} {:<10} {:<10}",
            "PID", "Total (ms)", "Delta (ms)", "CPU %", "Avg %"
        );
        println!("{}", "─".repeat(60));
    }

    // Main monitoring loop
    loop {
        // Wait for either a timer tick (every second) or Ctrl+C signal
        tokio::select! {
            // This branch executes every 1 second
            _ = interval.tick() => {
                // Increment sample counter
                sample_count += 1;

                // Get current total busy CPU time across all cores
                let mut total_busy: u64 = 0;
                // PerCpuArray stores one value per CPU core, so we sum them all
                if let Ok(values) = busy_cpu_time.get(&0, 0) {
                    total_busy = values.iter().sum::<u64>();
                }

                // Calculate how much CPU time was used since last check
                // This is the "delta" - the difference between current and previous reading
                let busy_delta = total_busy.saturating_sub(last_total_busy);
                let interval_sec = 1.0;  // We're sampling every 1 second

                if !json_output {
                    // Print sample header
                    println!("\n[Sample #{}] ────────────────────────────────────", sample_count);

                    // Global CPU usage mode
                    if pid_filter.is_none() {
                        // Calculate total available CPU time in this interval
                        // Formula: seconds × nanoseconds_per_second × number_of_CPUs
                        // Example: 1 sec × 1,000,000,000 ns × 4 CPUs = 4 billion nanoseconds available
                        let total_cpu_time_available = (interval_sec * 1_000_000_000.0 * num_cpus as f64) as u64;

                        // Calculate CPU utilization percentage
                        // Formula: (time_used / time_available) × 100
                        let cpu_utilization = if total_cpu_time_available > 0 {
                            (busy_delta as f64 / total_cpu_time_available as f64) * 100.0
                        } else {
                            0.0
                        };

                        // Print global CPU statistics
                        println!("{:<10} {:<12.2} {:<12.2} {:<10.2} {:<10}",
                            "GLOBAL",
                            total_busy as f64 / 1_000_000.0,      // Total time in milliseconds
                            busy_delta as f64 / 1_000_000.0,      // Delta time in milliseconds
                            cpu_utilization,                       // CPU percentage
                            "-"                                    // No average for global mode
                        );
                    }
                    // Per-PID tracking statistics
                    else {
                        // Get the list of PIDs we're monitoring
                        let pids_to_check = pid_filter.as_ref().unwrap();

                        // Process each PID we're tracking
                        for pid in pids_to_check {
                            // Try to get CPU time for this specific PID from the eBPF map
                            if let Ok(cpu_time) = pid_cpu_time.get(pid, 0) {
                                // Get the previous CPU time for this PID, or 0 if first time
                                let last_time = last_pid_times.get(pid).copied().unwrap_or(0);

                                // Calculate delta, how much CPU time this PID used since last check
                                let delta = cpu_time.saturating_sub(last_time);

                                // Convert delta to CPU percentage
                                // Delta is in nanoseconds, so divide by 1 billion to get seconds
                                // Then multiply by 100 to get percentage
                                let cpu_percent = (delta as f64 / 1_000_000_000.0) * 100.0;

                                // Update running statistics for this PID
                                let stats = pid_stats.entry(*pid).or_default();
                                stats.total_time = cpu_time;  // Update total cumulative time
                                stats.sample_count += 1;       // Increment sample count

                                // Update maximum CPU percentage if current is higher
                                stats.max_cpu_percent = stats.max_cpu_percent.max(cpu_percent);

                                // Calculate running average using weighted formula:
                                // new_avg = (old_avg × old_count + new_value) / new_count
                                stats.avg_cpu_percent =
                                    (stats.avg_cpu_percent * (stats.sample_count - 1) as f64 + cpu_percent)
                                    / stats.sample_count as f64;

                                // Print PID statistics for this sample
                                println!("{:<10} {:<12.2} {:<12.2} {:<10.2} {:<10.2}",
                                    pid,
                                    cpu_time as f64 / 1_000_000.0,     // Total CPU time in ms
                                    delta as f64 / 1_000_000.0,        // Delta in ms
                                    cpu_percent,                        // Current CPU %
                                    stats.avg_cpu_percent               // Running average CPU %
                                );

                                // Save current value as "previous" for next iteration
                                last_pid_times.insert(*pid, cpu_time);
                            } else {
                                // PID not found in map
                                println!("{:<10} {:<12} {:<12} {:<10} {:<10}",
                                    pid, "N/A", "N/A", "N/A", "N/A");
                            }
                        }
                    }

                    // Print separator line
                    println!("{}", "─".repeat(60));
                }

                // Save current total busy time for next iteration's delta calculation
                last_total_busy = total_busy;
            }

            // This branch executes when user presses Ctrl+C
            _ = signal::ctrl_c() => {
                // Print summary statistics
                if !json_output {
                    println!("\n\n═══════════════════════════════════════════════════════════");
                    println!("  CPU Monitor Summary");
                    println!("═══════════════════════════════════════════════════════════");
                    println!("  Total samples: {}", sample_count);
                    println!("  Duration: {} seconds", sample_count);

                    // If we were tracking specific PIDs, show their stats
                    if !pid_stats.is_empty() {
                        println!("\n  Per-PID Statistics:");
                        println!("  {:<10} {:<15} {:<15} {:<15}", "PID", "Total Time (ms)", "Avg CPU %", "Max CPU %");
                        println!("  {}", "─".repeat(60));

                        // Print summary for each PID that was monitored
                        for (pid, stats) in pid_stats.iter() {
                            println!("  {:<10} {:<15.2} {:<15.2} {:<15.2}",
                                pid,
                                stats.total_time as f64 / 1_000_000.0,  // Total time in milliseconds
                                stats.avg_cpu_percent,                  // Average CPU percentage
                                stats.max_cpu_percent                   // Maximum CPU percentage observed
                            );
                        }
                    }

                    println!("═══════════════════════════════════════════════════════════\n");
                }
                info!("CPU monitoring stopped");

                // Exit the loop, which ends the function
                break;
            }
        }
    }

    Ok(())
}
