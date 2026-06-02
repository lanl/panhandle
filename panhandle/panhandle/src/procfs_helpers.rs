use std::sync::Arc;

use procfs::process::all_processes;
use reqwest::Client;

// local imports
use crate::helpers::output_message;

/*
/*
    Method to return all information procfs finds about all processes.
    Takes no input parameters.
    Use for debugging only.
*/
pub fn get_all_proc_info() {
    if let Ok(procs) = all_processes() {
        for proc_res in procs {
            if let Ok(p) = proc_res
                && let Ok(stat) = p.stat()
            {
                // This prints the following example:
                //14:27:35 [INFO] panhandle::procfs: [panhandle/src/procfs.rs:10] Stat { pid: 395900, comm: "sudo", state: 'S', ppid: 395435, pgrp: 395900,
                //session: 395900, tty_nr: 34817, tpgid: 395901, flags: 4194368, minflt: 47, cminflt: 0, majflt: 0, cmajflt: 0, utime: 0, stime: 0, cutime: 0,
                //cstime: 0, priority: 20, nice: 0, num_threads: 1, itrealvalue: 0, starttime: 8616530, vsize: 153325568, rss: 267, rsslim: 18446744073709551615,
                //startcode: 94800910770176, endcode: 94800910944616, startstack: 140726370712480, kstkesp: 0, kstkeip: 0, signal: 0, blocked: 0, sigignore: 3149824,
                //sigcatch: 616967, wchan: 1, nswap: 0, cnswap: 0, exit_signal: Some(17), processor: Some(10), rt_priority: Some(0), policy: Some(0),
                //delayacct_blkio_ticks: Some(0), guest_time: Some(0), cguest_time: Some(0), start_data: Some(94800913045008), end_data: Some(94800913052000),
                //start_brk: Some(94800922886144), arg_start: Some(140726370718480), arg_end: Some(140726370718511), env_start: Some(140726370718511),
                //env_end: Some(140726370725866), exit_code: Some(0) }
                info!("{:?}", stat);
            }
        }
    }
}
*/

/*
    Method to check if processes or their children have memory faults greater than a certain threshold.
    Takes the desired threshold (integer, u64) and the desired output formatting (json, boolean) as input parameters.
*/
pub async fn get_major_faults(
    maj_fault_threshold: u64,
    use_json: &bool,
    http: &bool,
    syslog: &bool,
    hostname: &Arc<String>,
    global_url: &Arc<String>,
    syslog_address: &Arc<String>,
    client: &Client,
    debug: &bool,
) {
    // Get an iterator over all processes in /proc
    if let Ok(procs) = all_processes() {
        for proc_res in procs.flatten() {
            // Read /proc/[pid]/stat for this process
            // this stat() call is a potential TOCTOU issue
            // the process may no longer exist at the time that stat() is called on it
            // therefore we need to prevent / protect from that condition with the `if let Ok()` check
            if let Ok(stat) = proc_res.stat()
                && (stat.majflt > maj_fault_threshold || stat.cmajflt > maj_fault_threshold)
            {
                let plain_string = format!(
                    "PID: {}, Comm: {}, Major Faults: {}, Child Major Faults: {},",
                    stat.pid, stat.comm, stat.majflt, stat.cmajflt
                );
                let json_string: String = format!(
                    "{{\"PID\": \"{}\", \"Comm\": \"{}\", \"Major Faults\": \"{}\", \"Child Major Faults\": \"{}\"}}",
                    stat.pid, stat.comm, stat.majflt, stat.cmajflt
                );
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
    hostname: &Arc<String>,
    global_url: &Arc<String>,
    syslog_address: &Arc<String>,
    client: &Client,
    debug: &bool,
    pid_filter: &Option<Vec<u32>>,
) {
    // Get an iterator over all processes in /proc
    if let Ok(procs) = all_processes() {
        for proc_res in procs.flatten() {
            // Read /proc/[pid]/stat, /proc/[pid]/statm, and /proc/[pid]/status
            // these calls are potential TOCTOU issues - the process may no longer exist
            // therefore we need to prevent / protect from that condition with the `if let Ok()` checks
            if let Ok(stat) = proc_res.stat()
                && let Ok(statm) = proc_res.statm()
            {
                // Apply PID filter if provided
                if let Some(pids) = pid_filter
                    && !pids.contains(&(stat.pid as u32))
                {
                    continue; // Skip this process, it's not in filter list
                }

                // Read /proc/[pid]/status
                let status = proc_res.status().ok();

                // Extract vm_hwm and vm_rss from status if available
                let vm_hwm = status.as_ref().and_then(|s| s.vmhwm);
                let vm_rss = status.as_ref().and_then(|s| s.vmrss);

                // Convert various metrics to MB for readability
                let rss_mb = vm_rss.unwrap_or(0) / 1024;
                let vsize_mb = stat.vsize / (1024 * 1024);
                let vm_hwm_mb = vm_hwm.unwrap_or(0) / 1024;
                let resident_mb = (statm.resident * 4) / 1024; // pages to MB (4KB pages)
                let shared_mb = (statm.shared * 4) / 1024;
                let data_mb = (statm.data * 4) / 1024;
                let rss_pages = stat.rss;

                let plain_string = format!(
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

                let json_string = format!(
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
