use aya::{
    maps::{HashMap, perf::AsyncPerfEventArray},
    programs::{TracePoint, UProbe},
    util::online_cpus,
};
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
