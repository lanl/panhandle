use aya::maps::{HashMap, PerCpuArray};
use reqwest::Client;
extern crate simplelog;
use std::sync::Arc;

use crate::helpers::*;

// Structure to hold statistics for each monitored PID
#[derive(Default)]
pub struct PidStats {
    pub total_time: u64,      // Total cumulative CPU time
    pub sample_count: u64,    // Number of samples taken
    pub max_cpu_percent: f64, // Maximum CPU percentage observed
    pub avg_cpu_percent: f64, // Running average of CPU percentage
}

// cpu monitoring helper function
pub async fn monitor_cpu_usage(
    pid_cpu_time: &HashMap<aya::maps::MapData, u32, u64>,
    busy_cpu_time: &PerCpuArray<aya::maps::MapData, u64>,
    pid_filter: &Option<Vec<u32>>,
    json_output: &bool,
    http: &bool,
    syslog: &bool,
    verbose: &bool,
    hostname: &Arc<String>,
    syslog_address: &Arc<String>,
    global_url: &Arc<String>,
    client: &Client,
    debug: &bool,
    last_total_busy: &mut u64,
    last_pid_times: &mut std::collections::HashMap<u32, u64>,
    pid_stats: &mut std::collections::HashMap<u32, PidStats>,
    sample_count: &mut u64,
    poll_interval: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    *sample_count += 1;

    // Calculate total busy time for potential future use
    let mut total_busy: u64 = 0;
    if let Ok(values) = busy_cpu_time.get(&0, 0) {
        total_busy = values.iter().sum::<u64>();
    }

    // Convert poll interval to nanoseconds for CPU percentage calculation
    let interval_ns = (poll_interval as u64) * 1_000_000_000;

    // Determine which PIDs to check
    let pids_to_check: Vec<u32> = if let Some(filter) = pid_filter {
        filter.clone()
    } else {
        let mut all_pids = Vec::new();
        for pid in pid_cpu_time.keys().flatten() {
            all_pids.push(pid);
        }
        all_pids
    };

    // Process each PID
    for pid in pids_to_check {
        if let Ok(cpu_time) = pid_cpu_time.get(&pid, 0) {
            let last_time = last_pid_times.get(&pid).copied().unwrap_or(0);
            let delta = cpu_time.saturating_sub(last_time);

            // 100% = fully using one core, 200% = fully using two cores, etc.
            let cpu_percent = if interval_ns > 0 {
                (delta as f64 / interval_ns as f64) * 100.0
            } else {
                0.0
            };

            let stats = pid_stats.entry(pid).or_default();
            stats.total_time = cpu_time;
            stats.sample_count += 1;
            stats.max_cpu_percent = stats.max_cpu_percent.max(cpu_percent);
            stats.avg_cpu_percent = (stats.avg_cpu_percent * (stats.sample_count - 1) as f64
                + cpu_percent)
                / stats.sample_count as f64;

            // Get the command name for this PID
            let comm = if pid > 0 {
                get_process_name(pid).unwrap_or_else(|| "unknown".to_string())
            } else {
                "unknown".to_string()
            };

            // Only get parent info if verbose flag is set
            let (ppid, parent_comm) = if *verbose {
                if let Ok(parent_pid) = get_parent_pid(pid) {
                    let parent_name =
                        get_process_name(parent_pid).unwrap_or_else(|| "unknown".to_string());
                    (Some(parent_pid), Some(parent_name))
                } else {
                    (Some(0), Some("unknown".to_string()))
                }
            } else {
                (None, None)
            };

            // Build messages conditionally based on verbose flag
            let (plain_string, json_string) = if *verbose {
                let ppid_val = ppid.unwrap_or(0);
                let parent_comm_val = parent_comm.as_deref().unwrap_or("unknown");

                let plain = format!(
                    "Type: cpu, PID: {}, Comm: {}, PPID: {}, Parent_Comm: {}, Total_Time_ms: {:.2}, Delta_Time_ms: {:.2}, CPU%: {:.2}, Avg_CPU%: {:.2}, Max_CPU%: {:.2}",
                    pid,
                    comm,
                    ppid_val,
                    parent_comm_val,
                    cpu_time as f64 / 1_000_000.0,
                    delta as f64 / 1_000_000.0,
                    cpu_percent,
                    stats.avg_cpu_percent,
                    stats.max_cpu_percent
                );

                let json = format!(
                    "{{\"Type\": \"cpu\", \"PID\": {}, \"Comm\": \"{}\", \"PPID\": {}, \"Parent_Comm\": \"{}\", \"Total_Time_ms\": {:.2}, \"Delta_Time_ms\": {:.2}, \"CPU%\": {:.2}, \"Avg_CPU%\": {:.2}, \"Max_CPU%\": {:.2}}}",
                    pid,
                    comm,
                    ppid_val,
                    parent_comm_val,
                    cpu_time as f64 / 1_000_000.0,
                    delta as f64 / 1_000_000.0,
                    cpu_percent,
                    stats.avg_cpu_percent,
                    stats.max_cpu_percent
                );

                (plain, json)
            } else {
                // Non-verbose: exclude parent info
                let plain = format!(
                    "Type: cpu, PID: {}, Comm: {}, CPU%: {:.2}, Avg_CPU%: {:.2}, Max_CPU%: {:.2}",
                    pid, comm, cpu_percent, stats.avg_cpu_percent, stats.max_cpu_percent
                );

                let json = format!(
                    "{{\"Type\": \"cpu\", \"PID\": {}, \"Comm\": \"{}\", \"CPU%\": {:.2}, \"Avg_CPU%\": {:.2}, \"Max_CPU%\": {:.2}}}",
                    pid, comm, cpu_percent, stats.avg_cpu_percent, stats.max_cpu_percent
                );

                (plain, json)
            };

            output_message(
                http,
                syslog,
                hostname,
                syslog_address,
                global_url,
                json_output,
                &plain_string,
                &json_string,
                client,
                debug,
            )
            .await;

            last_pid_times.insert(pid, cpu_time);
        } else if pid_filter.is_some() {
            let comm = if pid > 0 {
                get_process_name(pid).unwrap_or_else(|| "unknown".to_string())
            } else {
                "unknown".to_string()
            };

            // conditionally include parent info in not_found messages too
            let (plain_string, json_string) = if *verbose {
                let (ppid, parent_comm) = if let Ok(parent_pid) = get_parent_pid(pid) {
                    let parent_name =
                        get_process_name(parent_pid).unwrap_or_else(|| "unknown".to_string());
                    (parent_pid, parent_name)
                } else {
                    (0, "unknown".to_string())
                };

                let plain = format!(
                    "Type: cpu, PID: {}, Comm: {}, PPID: {}, Parent_Comm: {}, Status: not_found",
                    pid, comm, ppid, parent_comm
                );
                let json = format!(
                    "{{\"Type\": \"cpu\", \"PID\": {}, \"Comm\": \"{}\", \"PPID\": {}, \"Parent_Comm\": \"{}\", \"Status\": \"not_found\"}}",
                    pid, comm, ppid, parent_comm
                );

                (plain, json)
            } else {
                let plain = format!("cpu: PID: {}, Comm: {}, Status: not_found", pid, comm);
                let json = format!(
                    "{{\"Type\": \"cpu\", \"PID\": {}, \"Comm\": \"{}\", \"Status\": \"not_found\"}}",
                    pid, comm
                );

                (plain, json)
            };

            output_message(
                http,
                syslog,
                hostname,
                syslog_address,
                global_url,
                json_output,
                &plain_string,
                &json_string,
                client,
                debug,
            )
            .await;
        }
    }

    *last_total_busy = total_busy;

    Ok(())
}
