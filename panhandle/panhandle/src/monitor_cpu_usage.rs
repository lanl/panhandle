use procfs::{
    CurrentSI,
    process::{Process, all_processes},
};
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

/// Per-PID CPU%, 100% = fully using one core, 200% = fully using two cores, etc.
pub(crate) fn calc_cpu_percent(delta_ns: u64, interval_ns: u64) -> f64 {
    if interval_ns > 0 {
        (delta_ns as f64 / interval_ns as f64) * 100.0
    } else {
        0.0
    }
}

/// System-wide CPU%, normalized to 0-100% (100% = every core fully busy), matching the
/// convention used by tools like top/htop's summary line rather than the per-PID scale.
pub(crate) fn calc_system_cpu_percent(
    busy_delta_ns: u64,
    interval_ns: u64,
    num_cpus: usize,
) -> f64 {
    if interval_ns > 0 && num_cpus > 0 {
        (busy_delta_ns as f64 / (interval_ns as f64 * num_cpus as f64) * 100.0).clamp(0.0, 100.0)
    } else {
        0.0
    }
}

// Fully-owned per-PID data gathered during the blocking scan phase, so the reporting
// loop afterward only needs to do async formatting/output work.
struct CpuEntry {
    pid: u32,
    comm: String,
    found: bool,
    ppid: Option<u32>,
    parent_comm: Option<String>,
    cpu_time: u64,
    delta: u64,
    cpu_percent: f64,
    avg_cpu_percent: f64,
    max_cpu_percent: f64,
}

// cpu monitoring helper function
pub async fn monitor_cpu_usage(
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

    let (needs_plain, needs_json) = output_needs(*http, *syslog, *json_output, *debug);

    // Convert poll interval to nanoseconds for CPU percentage calculation
    let interval_ns = (poll_interval as u64) * 1_000_000_000;

    // Gather all procfs lookups up front (off the async executor) so the reporting loop
    // below only does formatting/output work.
    let (entries, total_busy, num_cpus): (Vec<CpuEntry>, u64, usize) =
        tokio::task::block_in_place(|| {
            let ticks_per_second = procfs::ticks_per_second();

            // System-wide busy time, from /proc/stat's aggregate "cpu" line summed across
            // all cores; .cpu_time.len() gives the core count for free.
            let (total_busy, num_cpus) = match procfs::KernelStats::current() {
                Ok(stats) => {
                    let idle_ticks = stats.total.idle + stats.total.iowait.unwrap_or(0);
                    let total_ticks = stats.total.user
                        + stats.total.nice
                        + stats.total.system
                        + idle_ticks
                        + stats.total.irq.unwrap_or(0)
                        + stats.total.softirq.unwrap_or(0)
                        + stats.total.steal.unwrap_or(0);
                    let busy_ticks = total_ticks.saturating_sub(idle_ticks);
                    let busy_ns = busy_ticks * 1_000_000_000 / ticks_per_second;
                    (busy_ns, stats.cpu_time.len())
                }
                Err(_) => (0, 0),
            };

            // Determine which PIDs to check
            let pids_to_check: Vec<u32> = if let Some(filter) = pid_filter {
                filter.clone()
            } else {
                all_processes()
                    .map(|procs| procs.flatten().map(|p| p.pid() as u32).collect())
                    .unwrap_or_default()
            };

            let mut entries = Vec::new();

            // Process each PID
            for pid in pids_to_check {
                if let Ok(proc) = Process::new(pid as i32)
                    && let Ok(stat) = proc.stat()
                {
                    let cpu_time = (stat.utime + stat.stime) * 1_000_000_000 / ticks_per_second;
                    let last_time = last_pid_times.get(&pid).copied().unwrap_or(0);
                    let delta = cpu_time.saturating_sub(last_time);

                    let cpu_percent = calc_cpu_percent(delta, interval_ns);

                    let stats = pid_stats.entry(pid).or_default();
                    stats.total_time = cpu_time;
                    stats.sample_count += 1;
                    stats.max_cpu_percent = stats.max_cpu_percent.max(cpu_percent);
                    stats.avg_cpu_percent =
                        (stats.avg_cpu_percent * (stats.sample_count - 1) as f64 + cpu_percent)
                            / stats.sample_count as f64;
                    let avg_cpu_percent = stats.avg_cpu_percent;
                    let max_cpu_percent = stats.max_cpu_percent;

                    // Only get parent info if verbose flag is set
                    let (ppid, parent_comm) = if *verbose {
                        if let Ok(parent_pid) = get_parent_pid(pid) {
                            let parent_name = get_process_name(parent_pid)
                                .unwrap_or_else(|| "unknown".to_string());
                            (Some(parent_pid), Some(parent_name))
                        } else {
                            (Some(0), Some("unknown".to_string()))
                        }
                    } else {
                        (None, None)
                    };

                    entries.push(CpuEntry {
                        pid,
                        comm: stat.comm,
                        found: true,
                        ppid,
                        parent_comm,
                        cpu_time,
                        delta,
                        cpu_percent,
                        avg_cpu_percent,
                        max_cpu_percent,
                    });

                    last_pid_times.insert(pid, cpu_time);
                } else if pid_filter.is_some() {
                    // conditionally include parent info in not_found messages too
                    let (ppid, parent_comm) = if *verbose {
                        if let Ok(parent_pid) = get_parent_pid(pid) {
                            let parent_name = get_process_name(parent_pid)
                                .unwrap_or_else(|| "unknown".to_string());
                            (Some(parent_pid), Some(parent_name))
                        } else {
                            (Some(0), Some("unknown".to_string()))
                        }
                    } else {
                        (None, None)
                    };

                    entries.push(CpuEntry {
                        pid,
                        comm: "unknown".to_string(),
                        found: false,
                        ppid,
                        parent_comm,
                        cpu_time: 0,
                        delta: 0,
                        cpu_percent: 0.0,
                        avg_cpu_percent: 0.0,
                        max_cpu_percent: 0.0,
                    });
                }
            }

            (entries, total_busy, num_cpus)
        });

    for entry in entries {
        if entry.found {
            // Build messages conditionally based on verbose flag
            let (plain_string, json_string) = if *verbose {
                let ppid_val = entry.ppid.unwrap_or(0);
                let parent_comm_val = entry.parent_comm.as_deref().unwrap_or("unknown");

                let plain = if needs_plain {
                    format!(
                        "Type: cpu, PID: {}, Comm: {}, PPID: {}, Parent_Comm: {}, Total_Time_ms: {:.2}, Delta_Time_ms: {:.2}, CPU%: {:.2}, Avg_CPU%: {:.2}, Max_CPU%: {:.2}",
                        entry.pid,
                        entry.comm,
                        ppid_val,
                        parent_comm_val,
                        entry.cpu_time as f64 / 1_000_000.0,
                        entry.delta as f64 / 1_000_000.0,
                        entry.cpu_percent,
                        entry.avg_cpu_percent,
                        entry.max_cpu_percent
                    )
                } else {
                    String::new()
                };

                let json = if needs_json {
                    format!(
                        "{{\"Type\": \"cpu\", \"PID\": {}, \"Comm\": \"{}\", \"PPID\": {}, \"Parent_Comm\": \"{}\", \"Total_Time_ms\": {:.2}, \"Delta_Time_ms\": {:.2}, \"CPU%\": {:.2}, \"Avg_CPU%\": {:.2}, \"Max_CPU%\": {:.2}}}",
                        entry.pid,
                        entry.comm,
                        ppid_val,
                        parent_comm_val,
                        entry.cpu_time as f64 / 1_000_000.0,
                        entry.delta as f64 / 1_000_000.0,
                        entry.cpu_percent,
                        entry.avg_cpu_percent,
                        entry.max_cpu_percent
                    )
                } else {
                    String::new()
                };

                (plain, json)
            } else {
                // Non-verbose: exclude parent info
                let plain = if needs_plain {
                    format!(
                        "Type: cpu, PID: {}, Comm: {}, CPU%: {:.2}, Avg_CPU%: {:.2}, Max_CPU%: {:.2}",
                        entry.pid,
                        entry.comm,
                        entry.cpu_percent,
                        entry.avg_cpu_percent,
                        entry.max_cpu_percent
                    )
                } else {
                    String::new()
                };

                let json = if needs_json {
                    format!(
                        "{{\"Type\": \"cpu\", \"PID\": {}, \"Comm\": \"{}\", \"CPU%\": {:.2}, \"Avg_CPU%\": {:.2}, \"Max_CPU%\": {:.2}}}",
                        entry.pid,
                        entry.comm,
                        entry.cpu_percent,
                        entry.avg_cpu_percent,
                        entry.max_cpu_percent
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
                json_output,
                &plain_string,
                &json_string,
                client,
                debug,
            )
            .await;
        } else {
            let (plain_string, json_string) = if *verbose {
                let ppid_val = entry.ppid.unwrap_or(0);
                let parent_comm_val = entry.parent_comm.as_deref().unwrap_or("unknown");

                let plain = if needs_plain {
                    format!(
                        "Type: cpu, PID: {}, Comm: {}, PPID: {}, Parent_Comm: {}, Status: not_found",
                        entry.pid, entry.comm, ppid_val, parent_comm_val
                    )
                } else {
                    String::new()
                };
                let json = if needs_json {
                    format!(
                        "{{\"Type\": \"cpu\", \"PID\": {}, \"Comm\": \"{}\", \"PPID\": {}, \"Parent_Comm\": \"{}\", \"Status\": \"not_found\"}}",
                        entry.pid, entry.comm, ppid_val, parent_comm_val
                    )
                } else {
                    String::new()
                };

                (plain, json)
            } else {
                let plain = if needs_plain {
                    format!(
                        "cpu: PID: {}, Comm: {}, Status: not_found",
                        entry.pid, entry.comm
                    )
                } else {
                    String::new()
                };
                let json = if needs_json {
                    format!(
                        "{{\"Type\": \"cpu\", \"PID\": {}, \"Comm\": \"{}\", \"Status\": \"not_found\"}}",
                        entry.pid, entry.comm
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
                json_output,
                &plain_string,
                &json_string,
                client,
                debug,
            )
            .await;
        }
    }

    // System-wide CPU%: busy time accumulated across all cores since the last poll,
    // normalized to 0-100% (100% = every core fully busy), matching the convention
    // used by tools like top/htop's summary line rather than this file's per-PID
    // "100% = one core" scale.
    if num_cpus > 0 {
        let busy_delta = total_busy.saturating_sub(*last_total_busy);
        let system_cpu_percent = calc_system_cpu_percent(busy_delta, interval_ns, num_cpus);

        let plain_string = if needs_plain {
            format!(
                "Type: cpu_system, CPU%: {:.2}, Num_CPUs: {}, Busy_Delta_ms: {:.2}",
                system_cpu_percent,
                num_cpus,
                busy_delta as f64 / 1_000_000.0
            )
        } else {
            String::new()
        };
        let json_string = if needs_json {
            format!(
                "{{\"Type\": \"cpu_system\", \"CPU%\": {:.2}, \"Num_CPUs\": {}, \"Busy_Delta_ms\": {:.2}}}",
                system_cpu_percent,
                num_cpus,
                busy_delta as f64 / 1_000_000.0
            )
        } else {
            String::new()
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

    *last_total_busy = total_busy;

    Ok(())
}
