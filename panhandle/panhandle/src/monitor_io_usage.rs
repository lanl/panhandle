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
        if let Some(pids) = pid_list
            && !pids.contains(&(pid as u32))
        {
            continue;
        }

        // Get process stats (for comm and ppid)
        let stat = match proc.stat() {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Get IO stats from /proc/[pid]/io
        let io = match proc.io() {
            Ok(io_stats) => io_stats,
            Err(_) => continue, // skip process if we can't read IO stats
        };

        // Count open file descriptors and unique inodes
        let fd_path = format!("/proc/{}/fd", pid);
        let mut unique_inodes = HashSet::new();
        let mut fd_count = 0;

        if let Ok(entries) = std::fs::read_dir(&fd_path) {
            for entry in entries.flatten() {
                fd_count += 1;

                // Get inode number from the file descriptor
                if let Ok(metadata) = entry.metadata() {
                    unique_inodes.insert(metadata.ino());
                }
            }
        }

        // Skip processes with no IO activity and no open files
        if io.read_bytes == 0
            && io.write_bytes == 0
            && io.syscr == 0
            && io.syscw == 0
            && unique_inodes.is_empty()
        {
            continue;
        }

        // Get parent process info
        let ppid = stat.ppid as u32;
        let parent_comm = if ppid > 0 {
            get_process_name(ppid).unwrap_or_else(|| "unknown".to_string())
        } else {
            "unknown".to_string()
        };

        // Report stats
        report_io_and_inode_stats(
            pid as u32,
            &stat.comm,
            ppid,
            &parent_comm,
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
    ppid: u32,
    parent_comm: &str,
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
    hostname: &Arc<String>,
    syslog_address: &Arc<String>,
    http_url: &Arc<String>,
    client: &Client,
) {
    // format plaintext string
    let plain_string = format!(
        "PID: {}, Comm: {}, PPID: {}, Parent_Comm: {}, \
         Read_Count: {}, Write_Count: {}, Read_Bytes: {}, Write_Bytes: {}, \
         Open_FDs: {}, Unique_Inodes: {}",
        pid,
        comm,
        ppid,
        parent_comm,
        read_count,
        write_count,
        read_bytes,
        write_bytes,
        open_fds,
        unique_inodes
    );

    // format json string
    let json_value = json!({
        "PID": pid,
        "Comm": comm,
        "PPID": ppid,
        "Parent_Comm": parent_comm,
        "Read_Count": read_count,
        "Write_Count": write_count,
        "Read_Bytes": read_bytes,
        "Write_Bytes": write_bytes,
        "Open_FDs": open_fds,
        "Unique_Inodes": unique_inodes,
    });

    let json_string = json_value.to_string();

    // send via output message
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
