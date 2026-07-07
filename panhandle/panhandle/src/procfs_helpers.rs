use std::sync::Arc;

use procfs::process::all_processes;
use reqwest::Client;

use crate::helpers::{get_parent_pid, get_process_name, output_message};

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

                let (plain_string, json_string) = if *verbose {
                    let ppid_val = ppid.unwrap_or(0);
                    let parent_comm_val = parent_comm.as_deref().unwrap_or("unknown");

                    let plain = format!(
                        "PID: {}, Comm: {}, PPID: {}, Parent_Comm: {}, Major Faults: {}, Child Major Faults: {}",
                        stat.pid, stat.comm, ppid_val, parent_comm_val, stat.majflt, stat.cmajflt
                    );

                    let json = format!(
                        "{{\"PID\": \"{}\", \"Comm\": \"{}\", \"PPID\": \"{}\", \"Parent_Comm\": \"{}\", \"Major Faults\": \"{}\", \"Child Major Faults\": \"{}\"}}",
                        stat.pid, stat.comm, ppid_val, parent_comm_val, stat.majflt, stat.cmajflt
                    );

                    (plain, json)
                } else {
                    let plain = format!(
                        "PID: {}, Comm: {}, Major Faults: {}, Child Major Faults: {}",
                        stat.pid, stat.comm, stat.majflt, stat.cmajflt
                    );

                    let json = format!(
                        "{{\"PID\": \"{}\", \"Comm\": \"{}\", \"Major Faults\": \"{}\", \"Child Major Faults\": \"{}\"}}",
                        stat.pid, stat.comm, stat.majflt, stat.cmajflt
                    );

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
    }
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
    - Resident (MB): number of pages in physical RAM, similar to RSS but from different /proc source
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
                let resident_mb = (statm.resident * 4) / 1024;
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

                let (plain_string, json_string) = if *verbose {
                    let ppid_val = ppid.unwrap_or(0);
                    let parent_comm_val = parent_comm.as_deref().unwrap_or("unknown");

                    let plain = format!(
                        "PID: {}, Comm: {}, PPID: {}, Parent_Comm: {}, RSS: {} MB, RSS: {} pages, Peak RSS: {} MB, VSize: {} MB, Resident: {} MB, Shared: {} MB, Data+Stack: {} MB",
                        stat.pid,
                        stat.comm,
                        ppid_val,
                        parent_comm_val,
                        rss_mb,
                        rss_pages,
                        vm_hwm_mb,
                        vsize_mb,
                        resident_mb,
                        shared_mb,
                        data_mb
                    );

                    let json = format!(
                        "{{\"PID\": \"{}\", \"Comm\": \"{}\", \"PPID\": \"{}\", \"Parent_Comm\": \"{}\", \"RSS_MB\": \"{}\", \"RSS_Pages\": \"{}\", \"Peak_RSS_MB\": \"{}\", \"VSize_MB\": \"{}\", \"Resident_MB\": \"{}\", \"Shared_MB\": \"{}\", \"Data_Stack_MB\": \"{}\"}}",
                        stat.pid,
                        stat.comm,
                        ppid_val,
                        parent_comm_val,
                        rss_mb,
                        rss_pages,
                        vm_hwm_mb,
                        vsize_mb,
                        resident_mb,
                        shared_mb,
                        data_mb
                    );

                    (plain, json)
                } else {
                    let plain = format!(
                        "PID: {}, Comm: {}, RSS: {} MB, RSS: {} pages, Peak RSS: {} MB, VSize: {} MB, Resident: {} MB, Shared: {} MB, Data+Stack: {} MB",
                        stat.pid,
                        stat.comm,
                        rss_mb,
                        rss_pages,
                        vm_hwm_mb,
                        vsize_mb,
                        resident_mb,
                        shared_mb,
                        data_mb
                    );

                    let json = format!(
                        "{{\"PID\": \"{}\", \"Comm\": \"{}\", \"RSS_MB\": \"{}\", \"RSS_Pages\": \"{}\", \"Peak_RSS_MB\": \"{}\", \"VSize_MB\": \"{}\", \"Resident_MB\": \"{}\", \"Shared_MB\": \"{}\", \"Data_Stack_MB\": \"{}\"}}",
                        stat.pid,
                        stat.comm,
                        rss_mb,
                        rss_pages,
                        vm_hwm_mb,
                        vsize_mb,
                        resident_mb,
                        shared_mb,
                        data_mb
                    );

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
    }
}