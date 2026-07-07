use std::{collections::HashSet, os::unix::fs::MetadataExt, sync::Arc};

use reqwest::Client;
use serde_json::json;

use crate::helpers::*;

/* Monitor both IO statistics and inode counts for all processes
Output messages contain:
- Read_Count: Total number of read system calls since process start (syscr)
- Write_Count: Total number of write system calls since process start (syscw)
- Read_Bytes: Total bytes read from storage (cumulative since process start)
- Write_Bytes: Total bytes written to storage (cumulative since process start)
- Open_FDs: Current number of open file descriptors
- Unique_Inodes: Current number of unique inodes being accessed. Usually the same as Open_FDS, but Multiple FDs can sometimes point to one inode.
 */
pub async fn monitor_io_usage(
    json_output: &bool,
    http: &bool,
    syslog: &bool,
    debug: &bool,
    verbose: &bool,
    hostname: &Arc<String>,
    syslog_address: &Arc<String>,
    global_url: &Arc<String>,
    client: &Client,
    pid_list: &Option<Vec<u32>>,
) -> Result<(), Box<dyn std::error::Error>> {
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

        if let Some(pids) = pid_list
            && !pids.contains(&(pid as u32))
        {
            continue;
        }

        let stat = match proc.stat() {
            Ok(s) => s,
            Err(_) => continue,
        };

        let io = match proc.io() {
            Ok(io_stats) => io_stats,
            Err(_) => continue,
        };

        let fd_path = format!("/proc/{}/fd", pid);
        let mut unique_inodes = HashSet::new();
        let mut fd_count = 0;

        if let Ok(entries) = std::fs::read_dir(&fd_path) {
            for entry in entries.flatten() {
                fd_count += 1;

                if let Ok(metadata) = entry.metadata() {
                    unique_inodes.insert(metadata.ino());
                }
            }
        }

        if io.read_bytes == 0
            && io.write_bytes == 0
            && io.syscr == 0
            && io.syscw == 0
            && unique_inodes.is_empty()
        {
            continue;
        }

        // Retrieve parent process info only if verbose flag is set
        let (ppid, parent_comm) = if *verbose {
            let ppid = stat.ppid as u32;
            let parent_comm = if ppid > 0 {
                get_process_name(ppid).unwrap_or_else(|| "unknown".to_string())
            } else {
                "unknown".to_string()
            };
            (Some(ppid), Some(parent_comm))
        } else {
            (None, None)
        };

        report_io_and_inode_stats(
            pid as u32,
            &stat.comm,
            ppid,
            parent_comm.as_deref(),
            io.syscr,
            io.syscw,
            io.read_bytes,
            io.write_bytes,
            fd_count,
            unique_inodes.len(),
            json_output,
            http,
            syslog,
            debug,
            verbose,
            hostname,
            syslog_address,
            global_url,
            client,
        )
        .await;
    }

    Ok(())
}

/// Format and output IO stats for a single process
async fn report_io_and_inode_stats(
    pid: u32,
    comm: &str,
    ppid: Option<u32>,
    parent_comm: Option<&str>,
    read_count: u64,
    write_count: u64,
    read_bytes: u64,
    write_bytes: u64,
    open_fds: usize,
    unique_inodes: usize,
    json_output: &bool,
    http: &bool,
    syslog: &bool,
    debug_mode: &bool,
    verbose: &bool,
    hostname: &Arc<String>,
    syslog_address: &Arc<String>,
    http_url: &Arc<String>,
    client: &Client,
) {
    let (plain_string, json_string) = if *verbose {
        let ppid_val = ppid.unwrap_or(0);
        let parent_comm_val = parent_comm.unwrap_or("unknown");

        let plain = format!(
            "PID: {}, Comm: {}, PPID: {}, Parent_Comm: {}, \
             Read_Count: {}, Write_Count: {}, Read_Bytes: {}, Write_Bytes: {}, \
             Open_FDs: {}, Unique_Inodes: {}",
            pid,
            comm,
            ppid_val,
            parent_comm_val,
            read_count,
            write_count,
            read_bytes,
            write_bytes,
            open_fds,
            unique_inodes
        );

        let json_value = json!({
            "PID": pid,
            "Comm": comm,
            "PPID": ppid_val,
            "Parent_Comm": parent_comm_val,
            "Read_Count": read_count,
            "Write_Count": write_count,
            "Read_Bytes": read_bytes,
            "Write_Bytes": write_bytes,
            "Open_FDs": open_fds,
            "Unique_Inodes": unique_inodes,
        });

        (plain, json_value.to_string())
    } else {
        let plain = format!(
            "PID: {}, Comm: {}, \
             Read_Count: {}, Write_Count: {}, Read_Bytes: {}, Write_Bytes: {}, \
             Open_FDs: {}, Unique_Inodes: {}",
            pid,
            comm,
            read_count,
            write_count,
            read_bytes,
            write_bytes,
            open_fds,
            unique_inodes
        );

        let json_value = json!({
            "PID": pid,
            "Comm": comm,
            "Read_Count": read_count,
            "Write_Count": write_count,
            "Read_Bytes": read_bytes,
            "Write_Bytes": write_bytes,
            "Open_FDs": open_fds,
            "Unique_Inodes": unique_inodes,
        });

        (plain, json_value.to_string())
    };

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