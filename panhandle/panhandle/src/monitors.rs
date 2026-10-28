use crate::config::AppConfig;
use crate::error::Result;
use crate::output::OutputConfig;
use machine_info::Machine;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

/// Network statistics accumulated from eBPF events
pub type SharedNetStats = Arc<tokio::sync::Mutex<HashMap<u32, NetStats>>>;

/// Per-PID network statistics
#[derive(Debug, Default, Clone, Copy)]
pub struct NetStats {
    pub tcp_established: u32,
    pub tcp_syn_recv: u32,
    pub tcp_close_wait: u32,
    pub tcp_time_wait: u32,
    pub tcp_fin_wait: u32,
    pub udp_sockets: u32,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
}

impl NetStats {
    /// Check if there's any network activity
    pub fn has_activity(&self) -> bool {
        self.tcp_established > 0
            || self.tcp_syn_recv > 0
            || self.tcp_close_wait > 0
            || self.tcp_time_wait > 0
            || self.tcp_fin_wait > 0
            || self.udp_sockets > 0
            || self.bytes_sent > 0
            || self.bytes_recv > 0
            || self.packets_sent > 0
            || self.packets_recv > 0
    }
}

/// Per-PID CPU statistics
#[derive(Debug, Default, Clone, Copy)]
pub struct PidStats {
    pub cpu_percent: f64,
    pub user_time: u64,
    pub system_time: u64,
}

/// Monitor context shared across monitors
pub struct MonitorContext {
    pub config: AppConfig,
    pub output: OutputConfig,
    pub net_stats: SharedNetStats,
}

impl MonitorContext {
    pub fn new(config: AppConfig, output: OutputConfig) -> Self {
        Self {
            config,
            output,
            net_stats: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }
}

/// Run CPU monitoring loop
pub async fn run_cpu_monitor(ctx: MonitorContext) -> Result<()> {
    let mut last_total_busy: Option<u64> = None;
    let mut last_pid_times: HashMap<u32, u64> = HashMap::new();
    let mut pid_stats: HashMap<u32, PidStats> = HashMap::new();
    let mut sample_count = 0u64;

    loop {
        if let Err(e) = monitor_cpu_usage(
            &ctx.config,
            &ctx.output,
            &mut last_total_busy,
            &mut last_pid_times,
            &mut pid_stats,
            &mut sample_count,
        )
        .await
        {
            eprintln!("CPU monitoring error: {}", e);
        }
        sleep(Duration::from_secs(ctx.config.poll_seconds.into())).await;
    }
}

/// Run GPU monitoring loop
pub async fn run_gpu_monitor(ctx: MonitorContext) -> Result<()> {
    let machine = Machine::new();

    loop {
        if let Err(e) = monitor_gpu_usage(&ctx.config, &ctx.output, &machine).await {
            eprintln!("GPU monitoring error: {}", e);
        }
        sleep(Duration::from_secs(ctx.config.poll_seconds.into())).await;
    }
}

/// Run network monitoring loop (reads from shared net_stats)
pub async fn run_network_monitor(ctx: MonitorContext) -> Result<()> {
    loop {
        if let Err(e) = monitor_network_usage(&ctx.config, &ctx.output, &ctx.net_stats).await {
            eprintln!("Network monitoring error: {}", e);
        }
        sleep(Duration::from_secs(ctx.config.poll_seconds.into())).await;
    }
}

/// Run IO monitoring loop
pub async fn run_io_monitor(ctx: MonitorContext) -> Result<()> {
    loop {
        if let Err(e) = monitor_io_usage(&ctx.config, &ctx.output).await {
            eprintln!("IO monitoring error: {}", e);
        }
        sleep(Duration::from_secs(ctx.config.poll_seconds.into())).await;
    }
}

/// Run memory monitoring loop
pub async fn run_memory_monitor(ctx: MonitorContext) -> Result<()> {
    loop {
        if let Err(e) = monitor_memory_usage(&ctx.config, &ctx.output).await {
            eprintln!("Memory monitoring error: {}", e);
        }
        sleep(Duration::from_secs(ctx.config.poll_seconds.into())).await;
    }
}

/// Run memory faults monitoring loop
pub async fn run_memory_faults_monitor(ctx: MonitorContext) -> Result<()> {
    if let Some(threshold) = ctx.config.memory_faults {
        loop {
            if let Err(e) = monitor_memory_faults(&ctx.config, &ctx.output, threshold).await {
                eprintln!("Memory faults monitoring error: {}", e);
            }
            sleep(Duration::from_secs(ctx.config.poll_seconds.into())).await;
        }
    }
    Ok(())
}

/// Actual CPU monitoring implementation
async fn monitor_cpu_usage(
    config: &AppConfig,
    output: &OutputConfig,
    last_total_busy: &mut Option<u64>,
    last_pid_times: &mut HashMap<u32, u64>,
    pid_stats: &mut HashMap<u32, PidStats>,
    sample_count: &mut u64,
) -> Result<()> {
    let processes = procfs::process::all_processes()?;

    let mut current_total_busy = 0u64;
    let mut current_pid_times = HashMap::new();

    for proc in processes {
        let proc = proc?;
        let stat = match proc.stat() {
            Ok(s) => s,
            Err(_) => continue,
        };

        let pid = stat.pid as u32;
        let total_time =
            stat.utime + stat.stime + (stat.cutime.max(0) as u64) + (stat.cstime.max(0) as u64);
        current_pid_times.insert(pid, total_time);

        if config.pid_list.is_empty() || config.pid_list.contains(&pid) {
            current_total_busy += total_time;
        }
    }

    // Calculate CPU usage for tracked PIDs
    for (pid, &total_time) in &current_pid_times {
        if let Some(&last_time) = last_pid_times.get(pid) {
            let delta = total_time.saturating_sub(last_time);
            let cpu_percent = if let Some(last_total) = last_total_busy {
                let total_delta = current_total_busy.saturating_sub(*last_total);
                if total_delta > 0 {
                    (delta as f64 / total_delta as f64) * 100.0
                } else {
                    0.0
                }
            } else {
                0.0
            };

            if cpu_percent > 0.1 || config.debug {
                let stats = pid_stats.entry(*pid).or_default();
                stats.cpu_percent = cpu_percent;
                stats.user_time = delta; // simplified
                stats.system_time = 0; // would need separate tracking

                // Output if significant usage
                if cpu_percent > 1.0 || config.verbose {
                    let json = json!({
                        "type": "cpu",
                        "hostname": output.hostname.as_str(),
                        "pid": pid,
                        "cpu_percent": cpu_percent,
                        "timestamp": chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
                    });
                    output
                        .output_event(
                            &json.to_string(),
                            &format!("[CPU] PID {}: {:.1}%", pid, cpu_percent),
                        )
                        .await?;
                }
            }
        }
    }

    *last_total_busy = Some(current_total_busy);
    *last_pid_times = current_pid_times;
    *sample_count += 1;

    Ok(())
}

/// Actual GPU monitoring implementation
async fn monitor_gpu_usage(
    config: &AppConfig,
    output: &OutputConfig,
    _machine: &Machine,
) -> Result<()> {
    // GPU monitoring implementation would go here
    // For now, just a placeholder
    if config.debug {
        let json = json!({
            "type": "gpu",
            "hostname": output.hostname.as_str(),
            "message": "GPU monitoring not fully implemented",
            "timestamp": chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        });
        output
            .output_event(
                &json.to_string(),
                "[GPU] GPU monitoring not fully implemented",
            )
            .await?;
    }
    Ok(())
}

/// Actual network monitoring implementation (reads from shared stats)
async fn monitor_network_usage(
    config: &AppConfig,
    output: &OutputConfig,
    net_stats: &SharedNetStats,
) -> Result<()> {
    let stats = net_stats.lock().await;

    for (pid, ns) in stats.iter() {
        if (config.pid_list.is_empty() || config.pid_list.contains(pid)) && ns.has_activity() {
            let json = json!({
                "type": "network",
                "hostname": output.hostname.as_str(),
                "pid": pid,
                "tcp_established": ns.tcp_established,
                "tcp_syn_recv": ns.tcp_syn_recv,
                "tcp_close_wait": ns.tcp_close_wait,
                "tcp_time_wait": ns.tcp_time_wait,
                "tcp_fin_wait": ns.tcp_fin_wait,
                "udp_sockets": ns.udp_sockets,
                "bytes_sent": ns.bytes_sent,
                "bytes_recv": ns.bytes_recv,
                "packets_sent": ns.packets_sent,
                "packets_recv": ns.packets_recv,
                "timestamp": chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            });
            let text = format!(
                "[NET] PID {}: TCP est={} sent={} recv={}",
                pid, ns.tcp_established, ns.bytes_sent, ns.bytes_recv
            );
            output.output_event(&json.to_string(), &text).await?;
        }
    }

    // Prune old entries (optional)
    // stats.retain(|_, v| v.has_activity());

    Ok(())
}

/// Actual IO monitoring implementation
async fn monitor_io_usage(config: &AppConfig, output: &OutputConfig) -> Result<()> {
    let processes = procfs::process::all_processes()?;

    for proc in processes {
        let proc = proc?;
        let pid = proc.pid as u32;
        if (config.pid_list.is_empty() || config.pid_list.contains(&pid))
            && let Ok(io) = proc.io()
            && (io.read_bytes > 0 || io.write_bytes > 0)
        {
            let read_mb = io.read_bytes / (1024 * 1024);
            let write_mb = io.write_bytes / (1024 * 1024);

            let json = json!({
                "type": "io",
                "hostname": output.hostname.as_str(),
                "pid": pid,
                "read_bytes": io.read_bytes,
                "write_bytes": io.write_bytes,
                "read_mb": read_mb,
                "write_mb": write_mb,
                "timestamp": chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            });
            let text = format!("[IO] PID {}: read={}MB write={}MB", pid, read_mb, write_mb);
            output.output_event(&json.to_string(), &text).await?;
        }
    }
    Ok(())
}

/// Actual memory monitoring implementation
async fn monitor_memory_usage(config: &AppConfig, output: &OutputConfig) -> Result<()> {
    let processes = procfs::process::all_processes()?;

    for proc in processes {
        let proc = proc?;
        let pid = proc.pid as u32;
        if (config.pid_list.is_empty() || config.pid_list.contains(&pid))
            && let Ok(statm) = proc.statm()
        {
            let rss_pages = statm.resident;
            let rss_mb = (rss_pages * 4096) / (1024 * 1024); // 4KB pages

            if rss_mb > 0 {
                let json = json!({
                    "type": "memory",
                    "hostname": output.hostname.as_str(),
                    "pid": pid,
                    "rss_mb": rss_mb,
                    "timestamp": chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
                });
                let text = format!("[MEM] PID {}: RSS={}MB", pid, rss_mb);
                output.output_event(&json.to_string(), &text).await?;
            }
        }
    }
    Ok(())
}

/// Actual memory faults monitoring implementation
async fn monitor_memory_faults(
    config: &AppConfig,
    output: &OutputConfig,
    threshold: u64,
) -> Result<()> {
    let processes = procfs::process::all_processes()?;

    for proc in processes {
        let proc = proc?;
        let pid = proc.pid as u32;
        if (config.pid_list.is_empty() || config.pid_list.contains(&pid))
            && let Ok(stat) = proc.stat()
        {
            let major_faults = stat.majflt;
            if major_faults >= threshold {
                let json = json!({
                    "type": "memory_faults",
                    "hostname": output.hostname.as_str(),
                    "pid": pid,
                    "major_faults": major_faults,
                    "threshold": threshold,
                    "timestamp": chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
                });
                let text = format!(
                    "[MFAULT] PID {}: major faults={} (threshold={})",
                    pid, major_faults, threshold
                );
                output.output_event(&json.to_string(), &text).await?;
            }
        }
    }
    Ok(())
}
