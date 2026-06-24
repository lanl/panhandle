use std::sync::Arc;
use reqwest::Client;
use serde_json::json;

use crate::helpers::*;

/// IO monitoring main function using procfs
/// This function runs continuously and reports IO statistics for all processes
pub async fn monitor_io_usage(
    json_output: &bool,
    http: &bool,
    syslog: &bool,
    debug: &bool,
    hostname: &Arc<String>,
    syslog_address: &Arc<String>,
    global_url: &Arc<String>,
    client: &Client,
    pid_list: &Option<Vec<u32>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Get all processes
    let all_processes = match procfs::process::all_processes() {
        Ok(procs) => procs,
        Err(e) => {
            if *debug {
                eprintln!("Error reading processes: {}", e);
            }
            return Ok(());
        }
    };

    for proc_result in all_processes {
        let proc = match proc_result {
            Ok(p) => p,
            Err(_) => continue,
        };

        let pid = proc.pid();

        // Apply PID filter if provided
        if let Some(pids) = pid_list {
            if !pids.contains(&(pid as u32)) {
                continue;
            }
        }

        // Get process stats
        let stat = match proc.stat() {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Get IO stats from /proc/[pid]/io
        let io = match proc.io() {
            Ok(io_stats) => io_stats,
            Err(_) => continue, // skip process if there was an error reading it
        };

        // Skip if no activity
        if io.read_bytes == 0 && io.write_bytes == 0 && io.syscr == 0 && io.syscw == 0 {
            continue;
        }

        // Get parent process info
        let ppid = stat.ppid as u32;
        let parent_comm = if ppid > 0 {
            get_process_name(ppid).unwrap_or_else(|| "unknown".to_string())
        } else {
            "unknown".to_string()
        };

        // Report the statistics
        report_io_stats(
            pid as u32,
            &stat.comm,
            ppid,
            &parent_comm,
            io.syscr,
            io.syscw,
            io.read_bytes,
            io.write_bytes,
            json_output,
            http,
            syslog,
            debug,
            hostname,
            syslog_address,
            global_url,
            client,
        )
        .await;
    }

    Ok(())
}

/// Format and output IO statistics for a single process
async fn report_io_stats(
    pid: u32,
    comm: &str,
    ppid: u32,
    parent_comm: &str,
    read_count: u64,
    write_count: u64,
    read_bytes: u64,
    write_bytes: u64,
    json_output: &bool,
    http: &bool,
    syslog: &bool,
    debug_mode: &bool,
    hostname: &Arc<String>,
    syslog_address: &Arc<String>,
    http_url: &Arc<String>,
    client: &Client,
) {
    // Plain text format
    let plain_string = format!(
        "PID: {}, Comm: {}, PPID: {}, Parent_Comm: {}, Read_Count: {}, Write_Count: {}, Read_Bytes: {}, Write_Bytes: {}",
        pid,
        comm,
        ppid,
        parent_comm,
        read_count,
        write_count,
        read_bytes,
        write_bytes
    );

    // JSON format
    let json_value = json!({
        "PID": pid,
        "Comm": comm,
        "PPID": ppid,
        "Parent_Comm": parent_comm,
        "Read_Count": read_count,
        "Write_Count": write_count,
        "Read_Bytes": read_bytes,
        "Write_Bytes": write_bytes,
    });

    let json_string = json_value.to_string();

    // Output via configured channels
    output_message(
        http,
        syslog,
        hostname,
        syslog_address,
        http_url,
        json_output,
        &plain_string,
        &json_string,
        client,
        debug_mode,
    )
    .await;
}