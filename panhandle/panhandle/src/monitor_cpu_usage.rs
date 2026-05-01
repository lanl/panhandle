use aya::{
    maps::{HashMap, PerCpuArray},
    util::online_cpus,
};
use tokio::signal;
extern crate simplelog;
use simplelog::*;
use std::panic;

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
    pid_cpu_time: HashMap<aya::maps::MapData, u32, u64>, // Map storing CPU time per process ID
    busy_cpu_time: PerCpuArray<aya::maps::MapData, u64>, // Array storing busy time per CPU core
    pid_filter: Option<Vec<u32>>, // Optional list of PIDs to monitor (None = monitor all/global)
    json_output: bool,            // Flag to control output format
    poll_interval: u32,           // Defines how frequently information is polled and displayed
) -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::HashMap as StdHashMap;

    // Create a timer that ticks every poll_interval seconds
    let mut interval =
        tokio::time::interval(tokio::time::Duration::from_secs(poll_interval.into()));

    // Get the number of online CPU cores on the system
    let num_cpus = online_cpus()
        .map_err(|(msg, err)| format!("{}: {}", msg, err))?
        .len();

    // Counter to track how many samples have been taken
    let mut sample_count = 0u64;

    // Print startup information banner (only if not using JSON output)
    if !json_output {
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

    // Variables to store previous measurements
    let mut last_total_busy: u64 = 0; // Previous total busy CPU time across all cores
    let mut last_pid_times: StdHashMap<u32, u64> = StdHashMap::new(); // Previous CPU time per PID
    let mut pid_stats: StdHashMap<u32, PidStats> = StdHashMap::new(); // Accumulated statistics per PID

    // Print table header
    if !json_output {
        println!(
            "\n{:<10} {:<12} {:<12} {:<10} {:<10}",
            "PID", "Total (ms)", "Delta (ms)", "CPU %", "Avg %"
        );
        println!("{}", "─".repeat(60));
    }

    // Main monitoring loop
    loop {
        // Wait for either a timer tick (every poll interval) or Ctrl+C signal
        tokio::select! {
            // This branch executes every poll_interval seconds
            _ = interval.tick() => {
                // Increment sample counter
                sample_count += 1;

                // Get current total busy CPU time across all cores
                let mut total_busy: u64 = 0;
                // PerCpuArray stores one value per CPU core, so sum them all
                if let Ok(values) = busy_cpu_time.get(&0, 0) {
                    total_busy = values.iter().sum::<u64>();
                }

                // Calculate how much CPU time was used since last check
                // This is delta - the difference between current and previous reading
                let busy_delta = total_busy.saturating_sub(last_total_busy);
                let interval_sec = poll_interval as f64;  // Use actual polling interval

                if !json_output {
                    // Print sample header
                    println!("\n[Sample #{}] ────────────────────────────────────", sample_count);

                    // Global CPU usage mode
                    if let Some(pids_to_check) = &pid_filter {
                        // Per-PID tracking statistics
                        for pid in pids_to_check {
                            if let Ok(cpu_time) = pid_cpu_time.get(pid, 0) {
                                // Get the previous CPU time for this PID, or 0 if first time
                                let last_time = last_pid_times.get(pid).copied().unwrap_or(0);

                                // Calculate delta: how much CPU time this PID used since last check
                                let delta = cpu_time.saturating_sub(last_time);

                                // Convert delta to CPU percentage
                                let cpu_percent = (delta as f64 / (interval_sec * 1_000_000_000.0)) * 100.0;

                                // Update running stats for this PID
                                let stats = pid_stats.entry(*pid).or_default();
                                stats.total_time = cpu_time;  // Update total cumulative time
                                stats.sample_count += 1;       // Increment sample count

                                // Update maximum CPU percentage if current is higher
                                stats.max_cpu_percent = stats.max_cpu_percent.max(cpu_percent);

                                // Calculate average
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
                    else {
                        // Calculate total available CPU time in this interval
                        // Formula: seconds × nanoseconds_per_second × number_of_CPUs
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
                    println!("  Duration: {} seconds", sample_count * poll_interval as u64);

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
