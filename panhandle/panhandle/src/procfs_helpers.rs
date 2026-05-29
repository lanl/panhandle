use std::sync::Arc;

use procfs::process::all_processes;
use reqwest::Client;

// local imports
use crate::helpers::output_message;

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
    Takes the desired output formatting (json, boolean) as input parameters.
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
                // Read /proc/[pid]/status - this may fail for some processes due to permissions
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