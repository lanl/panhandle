use std::{collections::HashMap, sync::Arc};

use procfs::process::all_processes;
use reqwest::Client;

use crate::helpers::{
    format_owner, format_state, get_parent_pid, get_process_name, get_process_uid, output_message,
    output_needs, resolve_username,
};

// Fully-owned per-PID data gathered during the blocking scan phase, so the reporting
// loop afterward only needs to do async formatting/output work.
struct MajorFaultEntry {
    pid: i32,
    comm: String,
    ppid: Option<u32>,
    parent_comm: Option<String>,
    uid: Option<u32>,
    username: Option<String>,
    state: Option<char>,
    majflt: u64,
    cmajflt: u64,
}

/*
    Method to check if processes or their children have memory faults greater than a certain threshold.
    Takes the desired threshold (integer, u64) and the desired output formatting (json, boolean) as input parameters.
*/
pub async fn get_major_faults(
    maj_fault_threshold: u64,
    use_json: &bool,
    http: &bool,
    syslog: &bool,
    verbose: &bool,
    hostname: &Arc<String>,
    global_url: &Arc<String>,
    syslog_address: &Arc<String>,
    client: &Client,
    debug: &bool,
) {
    let (needs_plain, needs_json) = output_needs(*http, *syslog, *use_json, *debug);

    // Gather all procfs data up front (off the async executor) so the reporting loop
    // below only does formatting/output work.
    let entries: Vec<MajorFaultEntry> = tokio::task::block_in_place(|| {
        let mut entries = Vec::new();
        // Cache of uid -> username, scoped to this single poll, so N processes owned by
        // the same user cost one username lookup instead of N when --verbose is set --
        // this can hit network-backed NSS (LDAP).
        let mut username_cache: HashMap<u32, String> = HashMap::new();

        if let Ok(procs) = all_processes() {
            for proc_res in procs.flatten() {
                if let Ok(stat) = proc_res.stat()
                    && (stat.majflt > maj_fault_threshold || stat.cmajflt > maj_fault_threshold)
                {
                    // Retrieve parent process info only if verbose flag is set
                    let (ppid, parent_comm) = if *verbose {
                        if let Ok(parent_pid) = get_parent_pid(stat.pid as u32) {
                            let parent_name = get_process_name(parent_pid)
                                .unwrap_or_else(|| "unknown".to_string());
                            (Some(parent_pid), Some(parent_name))
                        } else {
                            (Some(0), Some("unknown".to_string()))
                        }
                    } else {
                        (None, None)
                    };

                    // Retrieve owner info only if verbose flag is set
                    let (uid, username, state) = if *verbose {
                        let (uid, username) = match get_process_uid(stat.pid as u32) {
                            Some(uid) => {
                                let username = username_cache
                                    .entry(uid)
                                    .or_insert_with(|| resolve_username(uid))
                                    .clone();
                                (Some(uid), Some(username))
                            }
                            None => (None, Some("unknown".to_string())),
                        };
                        (uid, username, Some(stat.state))
                    } else {
                        (None, None, None)
                    };

                    entries.push(MajorFaultEntry {
                        pid: stat.pid,
                        comm: stat.comm,
                        ppid,
                        parent_comm,
                        uid,
                        username,
                        state,
                        majflt: stat.majflt,
                        cmajflt: stat.cmajflt,
                    });
                }
            }
        }

        entries
    });

    for entry in entries {
        let (plain_string, json_string) = if *verbose {
            let ppid_val = entry.ppid.unwrap_or(0);
            let parent_comm_val = entry.parent_comm.as_deref().unwrap_or("unknown");
            let (uid_val, username_val) = format_owner(entry.uid, entry.username.as_deref());
            let state_val = format_state(entry.state);

            let plain = if needs_plain {
                format!(
                    "Type: mem, PID: {}, Comm: {}, PPID: {}, Parent_Comm: {}, UID: {}, Username: {}, State: {}, Maj_Faults: {}, Child_Maj_Faults: {}",
                    entry.pid,
                    entry.comm,
                    ppid_val,
                    parent_comm_val,
                    uid_val,
                    username_val,
                    state_val,
                    entry.majflt,
                    entry.cmajflt
                )
            } else {
                String::new()
            };

            let json = if needs_json {
                format!(
                    "{{\"Type\": \"fault\", \"PID\": \"{}\", \"Comm\": \"{}\", \"PPID\": \"{}\", \"Parent_Comm\": \"{}\", \"UID\": \"{}\", \"Username\": \"{}\", \"State\": \"{}\", \"Maj_Faults\": \"{}\", \"Child_Maj_Faults\": \"{}\"}}",
                    entry.pid,
                    entry.comm,
                    ppid_val,
                    parent_comm_val,
                    uid_val,
                    username_val,
                    state_val,
                    entry.majflt,
                    entry.cmajflt
                )
            } else {
                String::new()
            };

            (plain, json)
        } else {
            let plain = if needs_plain {
                format!(
                    "Type: fault, PID: {}, Comm: {}, Maj_Faults: {}, Child_Maj_Faults: {}",
                    entry.pid, entry.comm, entry.majflt, entry.cmajflt
                )
            } else {
                String::new()
            };

            let json = if needs_json {
                format!(
                    "{{\"Type\": \"fault\", \"PID\": \"{}\", \"Comm\": \"{}\", \"Maj_Faults\": \"{}\", \"Child_Maj_Faults\": \"{}\"}}",
                    entry.pid, entry.comm, entry.majflt, entry.cmajflt
                )
            } else {
                String::new()
            };

            (plain, json)
        };

        output_message(
            http,
            syslog,
            hostname,
            syslog_address,
            global_url,
            use_json,
            &plain_string,
            &json_string,
            client,
            debug,
        )
        .await;
    }
}

// Fully-owned per-PID data gathered during the blocking scan phase, so the reporting
// loop afterward only needs to do async formatting/output work.
struct MemoryUsageEntry {
    pid: i32,
    comm: String,
    ppid: Option<u32>,
    parent_comm: Option<String>,
    uid: Option<u32>,
    username: Option<String>,
    state: Option<char>,
    rss_mb: u64,
    rss_pages: u64,
    vm_hwm_mb: u64,
    vsize_mb: u64,
    shared_mb: u64,
    data_mb: u64,
}

/*
    Method to get memory usage information for all processes.

    Outputs:
    - PID
    - Comm: Command name
    - PPID (if verbose)
    - Parent_Comm (if verbose)
    - RSS (MB): Resident Set Size in megabytes
    - RSS (pages): Resident Set Size but in 4KB pages
    - Peak RSS (MB): maximum physical RAM the process has used since it started
    - VSize (MB): total virtual address space
    - Shared (MB): Shared memory pages
    - Data+Stack (MB): Data + stack size: size of process heap and stack regions (excludes code/text segment)
    Takes the desired output formatting (json, boolean) and pid filter as input parameters.
*/
pub async fn get_all_memory_usage(
    use_json: &bool,
    http: &bool,
    syslog: &bool,
    verbose: &bool,
    hostname: &Arc<String>,
    global_url: &Arc<String>,
    syslog_address: &Arc<String>,
    client: &Client,
    debug: &bool,
    pid_filter: &Option<Vec<u32>>,
) {
    let (needs_plain, needs_json) = output_needs(*http, *syslog, *use_json, *debug);

    // Gather all procfs data up front (off the async executor) so the reporting loop
    // below only does formatting/output work.
    let entries: Vec<MemoryUsageEntry> = tokio::task::block_in_place(|| {
        let mut entries = Vec::new();
        // Cache of uid -> username, scoped to this single poll, so N processes owned by
        // the same user cost one username lookup instead of N when --verbose is set --
        // this can hit network-backed NSS (LDAP).
        let mut username_cache: HashMap<u32, String> = HashMap::new();

        if let Ok(procs) = all_processes() {
            for proc_res in procs.flatten() {
                if let Ok(stat) = proc_res.stat()
                    && let Ok(statm) = proc_res.statm()
                {
                    if let Some(pids) = pid_filter
                        && !pids.contains(&(stat.pid as u32))
                    {
                        continue;
                    }

                    let status = proc_res.status().ok();

                    let vm_hwm = status.as_ref().and_then(|s| s.vmhwm);
                    let vm_rss = status.as_ref().and_then(|s| s.vmrss);

                    let rss_mb = vm_rss.unwrap_or(0) / 1024;
                    let vsize_mb = stat.vsize / (1024 * 1024);
                    let vm_hwm_mb = vm_hwm.unwrap_or(0) / 1024;
                    let shared_mb = (statm.shared * 4) / 1024;
                    let data_mb = (statm.data * 4) / 1024;
                    let rss_pages = stat.rss;

                    // Retrieve parent process info only if verbose flag is set
                    let (ppid, parent_comm) = if *verbose {
                        if let Ok(parent_pid) = get_parent_pid(stat.pid as u32) {
                            let parent_name = get_process_name(parent_pid)
                                .unwrap_or_else(|| "unknown".to_string());
                            (Some(parent_pid), Some(parent_name))
                        } else {
                            (Some(0), Some("unknown".to_string()))
                        }
                    } else {
                        (None, None)
                    };

                    // Owner info only if verbose flag is set. The real UID is already
                    // available for free here since `status` was fetched above for
                    // vm_hwm/vm_rss regardless of verbosity -- only the username
                    // resolution (which can hit network-backed NSS) is gated.
                    let (uid, username, state) = if *verbose {
                        let uid = status.as_ref().map(|s| s.ruid);
                        let username = uid.map(|uid| {
                            username_cache
                                .entry(uid)
                                .or_insert_with(|| resolve_username(uid))
                                .clone()
                        });
                        (uid, username, Some(stat.state))
                    } else {
                        (None, None, None)
                    };

                    entries.push(MemoryUsageEntry {
                        pid: stat.pid,
                        comm: stat.comm,
                        ppid,
                        parent_comm,
                        uid,
                        username,
                        state,
                        rss_mb,
                        rss_pages,
                        vm_hwm_mb,
                        vsize_mb,
                        shared_mb,
                        data_mb,
                    });
                }
            }
        }

        entries
    });

    for entry in entries {
        let (plain_string, json_string) = if *verbose {
            let ppid_val = entry.ppid.unwrap_or(0);
            let parent_comm_val = entry.parent_comm.as_deref().unwrap_or("unknown");
            let (uid_val, username_val) = format_owner(entry.uid, entry.username.as_deref());
            let state_val = format_state(entry.state);

            let plain = if needs_plain {
                format!(
                    "Type: mem, PID: {}, Comm: {}, PPID: {}, Parent_Comm: {}, UID: {}, Username: {}, State: {}, RSS_MB: {}, RSS_Pages: {}, Peak_RSS_MB: {}, VSize_MB: {}, Shared_MB: {}, Data_Stack_Size_MB: {}",
                    entry.pid,
                    entry.comm,
                    ppid_val,
                    parent_comm_val,
                    uid_val,
                    username_val,
                    state_val,
                    entry.rss_mb,
                    entry.rss_pages,
                    entry.vm_hwm_mb,
                    entry.vsize_mb,
                    entry.shared_mb,
                    entry.data_mb
                )
            } else {
                String::new()
            };

            let json = if needs_json {
                format!(
                    "{{\"Type\": \"mem\", \"PID\": \"{}\", \"Comm\": \"{}\", \"PPID\": \"{}\", \"Parent_Comm\": \"{}\", \"UID\": \"{}\", \"Username\": \"{}\", \"State\": \"{}\", \"RSS_MB\": \"{}\", \"RSS_Pages\": \"{}\", \"Peak_RSS_MB\": \"{}\", \"VSize_MB\": \"{}\", \"Shared_MB\": \"{}\", \"Data_Stack_Size_MB\": \"{}\"}}",
                    entry.pid,
                    entry.comm,
                    ppid_val,
                    parent_comm_val,
                    uid_val,
                    username_val,
                    state_val,
                    entry.rss_mb,
                    entry.rss_pages,
                    entry.vm_hwm_mb,
                    entry.vsize_mb,
                    entry.shared_mb,
                    entry.data_mb
                )
            } else {
                String::new()
            };

            (plain, json)
        } else {
            let plain = if needs_plain {
                format!(
                    "Type: mem, PID: {}, Comm: {}, RSS_MB: {}, RSS_Pages: {}, Peak_RSS_MB: {}, VSize_MB: {}, Shared_MB: {}, Data_Stack_Size_MB: {}",
                    entry.pid,
                    entry.comm,
                    entry.rss_mb,
                    entry.rss_pages,
                    entry.vm_hwm_mb,
                    entry.vsize_mb,
                    entry.shared_mb,
                    entry.data_mb
                )
            } else {
                String::new()
            };

            let json = if needs_json {
                format!(
                    "{{\"Type\": \"mem\", \"PID\": \"{}\", \"Comm\": \"{}\", \"RSS_MB\": \"{}\", \"RSS_Pages\": \"{}\", \"Peak_RSS_MB\": \"{}\", \"VSize_MB\": \"{}\", \"Shared_MB\": \"{}\", \"Data_Stack_Size_MB\": \"{}\"}}",
                    entry.pid,
                    entry.comm,
                    entry.rss_mb,
                    entry.rss_pages,
                    entry.vm_hwm_mb,
                    entry.vsize_mb,
                    entry.shared_mb,
                    entry.data_mb
                )
            } else {
                String::new()
            };

            (plain, json)
        };

        output_message(
            http,
            syslog,
            hostname,
            syslog_address,
            global_url,
            use_json,
            &plain_string,
            &json_string,
            client,
            debug,
        )
        .await;
    }
}
