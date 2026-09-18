use linux_taskstats::self;
use procfs::process::all_processes;
use reqwest::Client as reqwest_Client;
use std::sync::Arc;

use crate::helpers::*;

/// Plain-text rendering of a per-process delay/taskstats entry.
pub fn format_bound_prose(
    verbose: bool,
    pid: u32,
    comm: &str,
    ppid: Option<u32>,
    parent_comm: Option<&str>,
    cpu_wait_count: u64,
    cpu_wait_time_ms: u64,
    voluntary_switches: u64,
    nonvoluntary_switches: u64,
    blkio_wait_count: u64,
    blkio_wait_time_ms: u64,
    swapin_wait_count: u64,
    swapin_wait_time_ms: u64,
    page_wait_count: u64,
    page_wait_time_ms: u64,
) -> String {
    if verbose {
        let ppid_val = ppid.unwrap_or(0);
        let parent_comm_val = parent_comm.unwrap_or("unknown");
        format!(
            "Type: bound, PID: {}, Comm: {}, Parent PID: {}, Parent Comm: {}, \
            CPU Wait Count: {}, CPU Wait Time MS: {}, Voluntary Ctx Switches: {}, Nonvoluntary Ctx Switches: {}, \
            BlkIO Wait Count: {}, BlkIO Wait Time MS: {}, \
            Swapin Wait Count: {}, Swapin Wait Time MS: {}, \
            Page Wait Count: {}, Page Wait Time MS: {}",
            pid, comm, ppid_val, parent_comm_val,
            cpu_wait_count, cpu_wait_time_ms, voluntary_switches, nonvoluntary_switches,
            blkio_wait_count, blkio_wait_time_ms,
            swapin_wait_count, swapin_wait_time_ms,
            page_wait_count, page_wait_time_ms
        )
    } else {
        format!(
            "Type: bound, PID: {}, Comm: {}, \
            CPU Wait Count: {}, CPU Wait Time MS: {}, Voluntary Ctx Switches: {}, Nonvoluntary Ctx Switches: {}, \
            BlkIO Wait Count: {}, BlkIO Wait Time MS: {}, \
            Swapin Wait Count: {}, Swapin Wait Time MS: {}, \
            Page Wait Count: {}, Page Wait Time MS: {}",
            pid, comm,
            cpu_wait_count, cpu_wait_time_ms, voluntary_switches, nonvoluntary_switches,
            blkio_wait_count, blkio_wait_time_ms,
            swapin_wait_count, swapin_wait_time_ms,
            page_wait_count, page_wait_time_ms
        )
    }
}

/// JSON rendering of a per-process delay/taskstats entry, mirroring `format_bound_prose`.
pub fn format_bound_json(
    verbose: bool,
    pid: u32,
    comm: &str,
    ppid: Option<u32>,
    parent_comm: Option<&str>,
    cpu_wait_count: u64,
    cpu_wait_time_ms: u64,
    voluntary_switches: u64,
    nonvoluntary_switches: u64,
    blkio_wait_count: u64,
    blkio_wait_time_ms: u64,
    swapin_wait_count: u64,
    swapin_wait_time_ms: u64,
    page_wait_count: u64,
    page_wait_time_ms: u64,
) -> String {
    if verbose {
        let ppid_val = ppid.unwrap_or(0);
        let parent_comm_val = parent_comm.unwrap_or("unknown");
        format!(
            "{{\"Type\": \"bound\", \"PID\": {}, \"Comm\": {}, \"PPID\": {}, \"Parent_Comm\": {}, \
            \"CPU_Wait_Count\": {}, \"CPU_Wait_Time_MS\": {}, \"Voluntary_Ctx_Switches\": {}, \"Nonvoluntary_Ctx_Switches\": {}, \
            \"BlkIO_Wait_Count\": {}, \"BlkIO_Wait_Time_MS\": {}, \
            \"Swapin_Wait_Count\": {}, \"Swapin_Wait_Time_MS\": {}, \
            \"Page_Wait_Count\": {}, \"Page_Wait_Time_MS\": {}}}",
            pid,
            json_quoted(comm),
            ppid_val,
            json_quoted(parent_comm_val),
            cpu_wait_count, cpu_wait_time_ms, voluntary_switches, nonvoluntary_switches,
            blkio_wait_count, blkio_wait_time_ms,
            swapin_wait_count, swapin_wait_time_ms,
            page_wait_count, page_wait_time_ms
        )
    } else {
        format!(
            "{{\"Type\": \"bound\", \"PID\": {}, \"Comm\": {}, \
            \"CPU_Wait_Count\": {}, \"CPU_Wait_Time_MS\": {}, \"Voluntary_Ctx_Switches\": {}, \"Nonvoluntary_Ctx_Switches\": {}, \
            \"BlkIO_Wait_Count\": {}, \"BlkIO_Wait_Time_MS\": {}, \
            \"Swapin_Wait_Count\": {}, \"Swapin_Wait_Time_MS\": {}, \
            \"Page_Wait_Count\": {}, \"Page_Wait_Time_MS\": {}}}",
            pid,
            json_quoted(comm),
            cpu_wait_count, cpu_wait_time_ms, voluntary_switches, nonvoluntary_switches,
            blkio_wait_count, blkio_wait_time_ms,
            swapin_wait_count, swapin_wait_time_ms,
            page_wait_count, page_wait_time_ms
        )
    }
}

pub async fn monitor_process_bounds(
    use_json: &bool,
    http: &bool,
    syslog: &bool,
    verbose: &bool,
    hostname: &Arc<String>,
    global_url: &Arc<String>,
    syslog_address: &Arc<String>,
    client: &reqwest_Client,
    debug: &bool,
) {
    let (needs_plain, needs_json) = output_needs(*http, *syslog, *use_json, *debug);

    if let Ok(procs) = all_processes() {
        for proc_res in procs.flatten() {
            if let Ok(stat) = proc_res.stat() {
                if let Ok(bound_client) = linux_taskstats::Client::open() {
                    if let Ok(bound_stats) = bound_client.pid_stats(stat.pid as u32) {
                        let pid = stat.pid as u32;
                        let comm = stat.comm.clone();

                        // Retrieve parent process info only if verbose flag is set
                        let (ppid, parent_comm) = if *verbose {
                            let parent_pid = stat.ppid as u32;
                            let parent_name = get_process_name(parent_pid)
                                .unwrap_or_else(|| "unknown".to_string());
                            (Some(parent_pid), Some(parent_name))
                        } else {
                            (None, None)
                        };

                        // get required structs from taskstats
                        let delays = bound_stats.delays; // primary source to see bound stats; information relating to blocking/waiting
                        let ctx_switches = bound_stats.ctx_switches; // good for seeing cpu hangups involving context switches

                        // CPU bound indicators
                        let cpu_wait_count = delays.cpu.count; // number of delay values recorded
                        let cpu_wait_time_ms = delays.cpu.delay_total.as_millis() as u64; // cumulative total delay
                        let voluntary_switches = ctx_switches.voluntary; // total amount of voluntary ctx switches
                        let nonvoluntary_switches = ctx_switches.non_voluntary; // total amount of nonvoluntary ctx switches

                        // synchronous block I/O bound indicators
                        let blkio_wait_count = delays.blkio.count;
                        let blkio_wait_time_ms = delays.blkio.delay_total.as_millis() as u64;

                        // page fault delays, also I/O bound indicators (swap in only)
                        let swapin_wait_count = delays.swapin.count;
                        let swapin_wait_time_ms = delays.swapin.delay_total.as_millis() as u64;

                        // memory bound indicators: delay waiting for memory reclaim
                        let page_wait_count = delays.freepages.count;
                        let page_wait_time_ms = delays.freepages.delay_total.as_millis() as u64;

                        let plain_string = if needs_plain {
                            format_bound_prose(
                                *verbose,
                                pid,
                                &comm,
                                ppid,
                                parent_comm.as_deref(),
                                cpu_wait_count,
                                cpu_wait_time_ms,
                                voluntary_switches,
                                nonvoluntary_switches,
                                blkio_wait_count,
                                blkio_wait_time_ms,
                                swapin_wait_count,
                                swapin_wait_time_ms,
                                page_wait_count,
                                page_wait_time_ms,
                            )
                        } else {
                            String::new()
                        };

                        let json_string = if needs_json {
                            format_bound_json(
                                *verbose,
                                pid,
                                &comm,
                                ppid,
                                parent_comm.as_deref(),
                                cpu_wait_count,
                                cpu_wait_time_ms,
                                voluntary_switches,
                                nonvoluntary_switches,
                                blkio_wait_count,
                                blkio_wait_time_ms,
                                swapin_wait_count,
                                swapin_wait_time_ms,
                                page_wait_count,
                                page_wait_time_ms,
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
    }
}