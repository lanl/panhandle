use aya::{
    maps::{HashMap, PerCpuArray},
    util::online_cpus,
};
use reqwest::Client;
use serde_json::json;
use tokio::signal;
extern crate simplelog;
use chrono::Utc;
use simplelog::*;
use std::{panic, sync::Arc};

use crate::helpers::*;

// Structure to hold statistics for each monitored PID
#[derive(Default)]
struct PidStats {
    total_time: u64,      // Total cumulative CPU time
    sample_count: u64,    // Number of samples taken
    max_cpu_percent: f64, // Maximum CPU percentage observed
    avg_cpu_percent: f64, // Running average of CPU percentage
}

// cpu monitoring helper function
pub async fn monitor_cpu_usage(
    pid_cpu_time: HashMap<aya::maps::MapData, u32, u64>,
    busy_cpu_time: PerCpuArray<aya::maps::MapData, u64>,
    pid_filter: Option<Vec<u32>>,
    json_output: bool,
    poll_interval: u32,
    http: bool,
    syslog: bool,
    hostname: Arc<String>,
    syslog_address: Arc<String>,
    global_url: Arc<String>,
    client: Client,
    debug: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::HashMap as StdHashMap;

    let mut interval =
        tokio::time::interval(tokio::time::Duration::from_secs(poll_interval.into()));

    let num_cpus = online_cpus()
        .map_err(|(msg, err)| format!("{}: {}", msg, err))?
        .len();

    let mut sample_count = 0u64;

    // Print startup information banner (only if not using JSON output)
    if !json_output && !syslog && !http {
        info!("═══════════════════════════════════════════════════════════");
        info!("  CPU Usage Monitor Started");
        info!("  CPUs: {}", num_cpus);
        info!("  Poll Interval: {} seconds", poll_interval);
        if let Some(ref pids) = pid_filter {
            info!("  Tracking PIDs: {:?}", pids);
        } else {
            info!("  Mode: Global CPU usage");
        }
        info!("═══════════════════════════════════════════════════════════");
    }

    let mut last_total_busy: u64 = 0;
    let mut last_pid_times: StdHashMap<u32, u64> = StdHashMap::new();
    let mut pid_stats: StdHashMap<u32, PidStats> = StdHashMap::new();

    // Print table header only for console output
    if !json_output && !syslog && !http {
        println!(
            "\n{:<10} {:<12} {:<12} {:<10} {:<10}",
            "PID", "Total (ms)", "Delta (ms)", "CPU %", "Avg %"
        );
        println!("{}", "─".repeat(60));
    }

    loop {
        tokio::select! {
            _ = interval.tick() => {
                sample_count += 1;
                let timestamp = Utc::now().to_rfc3339();

                let mut total_busy: u64 = 0;
                if let Ok(values) = busy_cpu_time.get(&0, 0) {
                    total_busy = values.iter().sum::<u64>();
                }

                let busy_delta = total_busy.saturating_sub(last_total_busy);
                let interval_sec = poll_interval as f64;

                if let Some(pids_to_check) = &pid_filter {
                    // Per-PID tracking
                    for pid in pids_to_check {
                        if let Ok(cpu_time) = pid_cpu_time.get(pid, 0) {
                            let last_time = last_pid_times.get(pid).copied().unwrap_or(0);
                            let delta = cpu_time.saturating_sub(last_time);
                            let cpu_percent = (delta as f64 / (interval_sec * 1_000_000_000.0)) * 100.0;

                            let stats = pid_stats.entry(*pid).or_default();
                            stats.total_time = cpu_time;
                            stats.sample_count += 1;
                            stats.max_cpu_percent = stats.max_cpu_percent.max(cpu_percent);
                            stats.avg_cpu_percent =
                                (stats.avg_cpu_percent * (stats.sample_count - 1) as f64 + cpu_percent)
                                / stats.sample_count as f64;

                            // Create plain text message
                            let plain_string = format!(
                                "CPU_MONITOR hostname={} sample={} pid={} total_time_ms={:.2} delta_time_ms={:.2} cpu_percent={:.2} avg_cpu_percent={:.2}",
                                hostname,
                                sample_count,
                                pid,
                                cpu_time as f64 / 1_000_000.0,
                                delta as f64 / 1_000_000.0,
                                cpu_percent,
                                stats.avg_cpu_percent
                            );

                            // Create JSON message
                            let json_value = json!({
                                "event_type": "cpu_monitor",
                                "hostname": hostname.as_str(),
                                "timestamp": timestamp,
                                "sample": sample_count,
                                "pid": pid,
                                "total_time_ms": format!("{:.2}", cpu_time as f64 / 1_000_000.0),
                                "delta_time_ms": format!("{:.2}", delta as f64 / 1_000_000.0),
                                "cpu_percent": format!("{:.2}", cpu_percent),
                                "avg_cpu_percent": format!("{:.2}", stats.avg_cpu_percent),
                                "max_cpu_percent": format!("{:.2}", stats.max_cpu_percent),
                                "sample_count": stats.sample_count
                            });
                            let json_string = json_value.to_string();

                            // Send via output_message
                            output_message(
                                &http,
                                &syslog,
                                &hostname,
                                &syslog_address,
                                &global_url,
                                &json_output,
                                &plain_string,
                                &json_string,
                                &client,
                                &debug,
                            ).await;

                            last_pid_times.insert(*pid, cpu_time);
                        } else {
                            // PID not found
                            let plain_string = format!(
                                "CPU_MONITOR hostname={} sample={} pid={} status=not_found",
                                hostname, sample_count, pid
                            );
                            let json_value = json!({
                                "event_type": "cpu_monitor",
                                "hostname": hostname.as_str(),
                                "timestamp": timestamp,
                                "sample": sample_count,
                                "pid": pid,
                                "status": "not_found"
                            });
                            let json_string = json_value.to_string();

                            output_message(
                                &http,
                                &syslog,
                                &hostname,
                                &syslog_address,
                                &global_url,
                                &json_output,
                                &plain_string,
                                &json_string,
                                &client,
                                &debug,
                            ).await;
                        }
                    }
                } else {
                    // Global CPU monitoring
                    let total_cpu_time_available = (interval_sec * 1_000_000_000.0 * num_cpus as f64) as u64;
                    let cpu_utilization = if total_cpu_time_available > 0 {
                        (busy_delta as f64 / total_cpu_time_available as f64) * 100.0
                    } else {
                        0.0
                    };

                    // Create plain text message
                    let plain_string = format!(
                        "CPU_MONITOR hostname={} sample={} mode=global num_cpus={} total_time_ms={:.2} delta_time_ms={:.2} cpu_utilization_percent={:.2}",
                        hostname,
                        sample_count,
                        num_cpus,
                        total_busy as f64 / 1_000_000.0,
                        busy_delta as f64 / 1_000_000.0,
                        cpu_utilization
                    );

                    // Create JSON message
                    let json_value = json!({
                        "event_type": "cpu_monitor",
                        "hostname": hostname.as_str(),
                        "timestamp": timestamp,
                        "sample": sample_count,
                        "mode": "global",
                        "num_cpus": num_cpus,
                        "total_time_ms": format!("{:.2}", total_busy as f64 / 1_000_000.0),
                        "delta_time_ms": format!("{:.2}", busy_delta as f64 / 1_000_000.0),
                        "cpu_utilization_percent": format!("{:.2}", cpu_utilization),
                        "poll_interval_sec": poll_interval
                    });
                    let json_string = json_value.to_string();

                    // Send via output_message
                    output_message(
                        &http,
                        &syslog,
                        &hostname,
                        &syslog_address,
                        &global_url,
                        &json_output,
                        &plain_string,
                        &json_string,
                        &client,
                        &debug,
                    ).await;
                }

                last_total_busy = total_busy;
            }

            _ = signal::ctrl_c() => {
                // Print summary statistics
                if !json_output && !syslog && !http {
                    println!("\n\n═══════════════════════════════════════════════════════════");
                    println!("  CPU Monitor Summary");
                    println!("═══════════════════════════════════════════════════════════");
                    println!("  Total samples: {}", sample_count);
                    println!("  Duration: {} seconds", sample_count * poll_interval as u64);

                    if !pid_stats.is_empty() {
                        println!("\n  Per-PID Statistics:");
                        println!("  {:<10} {:<15} {:<15} {:<15}", "PID", "Total Time (ms)", "Avg CPU %", "Max CPU %");
                        println!("  {}", "─".repeat(60));

                        for (pid, stats) in pid_stats.iter() {
                            println!("  {:<10} {:<15.2} {:<15.2} {:<15.2}",
                                pid,
                                stats.total_time as f64 / 1_000_000.0,
                                stats.avg_cpu_percent,
                                stats.max_cpu_percent
                            );
                        }
                    }

                    println!("═══════════════════════════════════════════════════════════\n");
                }

                // Send summary via output_message
                let timestamp = Utc::now().to_rfc3339();
                let plain_string = format!(
                    "CPU_MONITOR_SUMMARY hostname={} total_samples={} duration_sec={} pids_monitored={}",
                    hostname,
                    sample_count,
                    sample_count * poll_interval as u64,
                    pid_stats.len()
                );

                let mut pid_summaries = Vec::new();
                for (pid, stats) in pid_stats.iter() {
                    pid_summaries.push(json!({
                        "pid": pid,
                        "total_time_ms": format!("{:.2}", stats.total_time as f64 / 1_000_000.0),
                        "avg_cpu_percent": format!("{:.2}", stats.avg_cpu_percent),
                        "max_cpu_percent": format!("{:.2}", stats.max_cpu_percent),
                        "sample_count": stats.sample_count
                    }));
                }

                let json_value = json!({
                    "event_type": "cpu_monitor_summary",
                    "hostname": hostname.as_str(),
                    "timestamp": timestamp,
                    "total_samples": sample_count,
                    "duration_sec": sample_count * poll_interval as u64,
                    "poll_interval_sec": poll_interval,
                    "num_cpus": num_cpus,
                    "pid_statistics": pid_summaries
                });
                let json_string = json_value.to_string();

                crate::helpers::output_message(
                    &http,
                    &syslog,
                    &hostname,
                    &syslog_address,
                    &global_url,
                    &json_output,
                    &plain_string,
                    &json_string,
                    &client,
                    &debug,
                ).await;

                info!("CPU monitoring stopped");
                break;
            }
        }
    }

    Ok(())
}
