use std::sync::{Arc, Mutex};

use aya::maps::{HashMap as AyaHashMap, MapData};
use linux_taskstats::{self};
use procfs::process::all_processes;
use reqwest::Client as reqwest_Client;

use crate::helpers::*;

// matches the ebpf side struct for monitoring if processes are network bound
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NetWaitStat {
    pub count: u64,
    pub total_ns: u64,
}

// plain old data requirement to access the keys of the hashmap
unsafe impl aya::Pod for NetWaitStat {}

pub type SharedNetWaitMap = Arc<Mutex<AyaHashMap<MapData, u32, NetWaitStat>>>;

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
    network_wait_count: u64,
    network_wait_time_ms: u64,
) -> String {
    if verbose {
        let ppid_val = ppid.unwrap_or(0);
        let parent_comm_val = parent_comm.unwrap_or("unknown");
        format!(
            "Type: bound, PID: {}, Comm: {}, Parent PID: {}, Parent Comm: {}, \
            CPU Wait Count: {}, CPU Wait Time MS: {}, Voluntary Ctx Switches: {}, Nonvoluntary Ctx Switches: {}, \
            BlkIO Wait Count: {}, BlkIO Wait Time MS: {}, \
            Swapin Wait Count: {}, Swapin Wait Time MS: {}, \
            Page Wait Count: {}, Page Wait Time MS: {}, \
            Network Wait Count: {}, Network Wait Time MS: {}",
            pid,
            comm,
            ppid_val,
            parent_comm_val,
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
            network_wait_count,
            network_wait_time_ms
        )
    } else {
        format!(
            "Type: bound, PID: {}, Comm: {}, \
            CPU Wait Count: {}, CPU Wait Time MS: {}, Voluntary Ctx Switches: {}, Nonvoluntary Ctx Switches: {}, \
            BlkIO Wait Count: {}, BlkIO Wait Time MS: {}, \
            Swapin Wait Count: {}, Swapin Wait Time MS: {}, \
            Page Wait Count: {}, Page Wait Time MS: {}, \
            Network Wait Count: {}, Network Wait Time MS: {}",
            pid,
            comm,
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
            network_wait_count,
            network_wait_time_ms
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
    network_wait_count: u64,
    network_wait_time_ms: u64,
) -> String {
    if verbose {
        let ppid_val = ppid.unwrap_or(0);
        let parent_comm_val = parent_comm.unwrap_or("unknown");
        format!(
            "{{\"Type\": \"bound\", \"PID\": {}, \"Comm\": {}, \"PPID\": {}, \"Parent_Comm\": {}, \
            \"CPU_Wait_Count\": {}, \"CPU_Wait_Time_MS\": {}, \"Voluntary_Ctx_Switches\": {}, \"Nonvoluntary_Ctx_Switches\": {}, \
            \"BlkIO_Wait_Count\": {}, \"BlkIO_Wait_Time_MS\": {}, \
            \"Swapin_Wait_Count\": {}, \"Swapin_Wait_Time_MS\": {}, \
            \"Page_Wait_Count\": {}, \"Page_Wait_Time_MS\": {}, \
            \"Network_Wait_Count\": {}, \"Network_Wait_Time_MS\": {}}}",
            pid,
            json_quoted(comm),
            ppid_val,
            json_quoted(parent_comm_val),
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
            network_wait_count,
            network_wait_time_ms
        )
    } else {
        format!(
            "{{\"Type\": \"bound\", \"PID\": {}, \"Comm\": {}, \
            \"CPU_Wait_Count\": {}, \"CPU_Wait_Time_MS\": {}, \"Voluntary_Ctx_Switches\": {}, \"Nonvoluntary_Ctx_Switches\": {}, \
            \"BlkIO_Wait_Count\": {}, \"BlkIO_Wait_Time_MS\": {}, \
            \"Swapin_Wait_Count\": {}, \"Swapin_Wait_Time_MS\": {}, \
            \"Page_Wait_Count\": {}, \"Page_Wait_Time_MS\": {}, \
            \"Network_Wait_Count\": {}, \"Network_Wait_Time_MS\": {}}}",
            pid,
            json_quoted(comm),
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
            network_wait_count,
            network_wait_time_ms
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
    net_wait: &SharedNetWaitMap,
) {
    let (needs_plain, needs_json) = output_needs(*http, *syslog, *use_json, *debug);

    // Track which pids we actually see this cycle so we can prune NET_WAIT of
    // entries for pids that have exited - otherwise the map grows unboundedly,
    // just like the SharedNetStats accumulator in network.rs.
    let mut live_pids: std::collections::HashSet<u32> = std::collections::HashSet::new();

    if let Ok(procs) = all_processes() {
        for proc_res in procs.flatten() {
            if let Ok(stat) = proc_res.stat()
                && let Ok(bound_client) = linux_taskstats::Client::open()
                && let Ok(bound_stats) = bound_client.pid_stats(stat.pid as u32)
            {
                let pid = stat.pid as u32;
                let comm = stat.comm.clone();
                live_pids.insert(pid);

                // Retrieve parent process info only if verbose flag is set
                let (ppid, parent_comm) = if *verbose {
                    let parent_pid = stat.ppid as u32;
                    let parent_name =
                        get_process_name(parent_pid).unwrap_or_else(|| "unknown".to_string());
                    (Some(parent_pid), Some(parent_name))
                } else {
                    (None, None)
                };

                // get required structs from taskstats
                let delays = bound_stats.delays;
                let ctx_switches = bound_stats.ctx_switches;

                // CPU bound indicators
                let cpu_wait_count = delays.cpu.count;
                let cpu_wait_time_ms = delays.cpu.delay_total.as_millis() as u64;
                let voluntary_switches = ctx_switches.voluntary;
                let nonvoluntary_switches = ctx_switches.non_voluntary;

                // synchronous block I/O bound indicators
                let blkio_wait_count = delays.blkio.count;
                let blkio_wait_time_ms = delays.blkio.delay_total.as_millis() as u64;

                // swap-in delays
                let swapin_wait_count = delays.swapin.count;
                let swapin_wait_time_ms = delays.swapin.delay_total.as_millis() as u64;

                // memory bound indicators
                let page_wait_count = delays.freepages.count;
                let page_wait_time_ms = delays.freepages.delay_total.as_millis() as u64;

                // network bound indicators, pulled from the NET_WAIT eBPF map
                // populated by the tcp_recvmsg kprobe/kretprobe pair. Cumulative
                // since the probes were attached, same as the taskstats counters
                // above - no reset needed on our end.
                let (network_wait_count, network_wait_time_ms) = {
                    let map = net_wait.lock().unwrap();
                    match map.get(&pid, 0) {
                        Ok(stat) => (stat.count, stat.total_ns / 1_000_000),
                        Err(_) => (0, 0),
                    }
                };

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
                        network_wait_count,
                        network_wait_time_ms,
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
                        network_wait_count,
                        network_wait_time_ms,
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

    // Prune NET_WAIT of pids we didn't see this cycle (i.e. they've exited).
    {
        let mut map = net_wait.lock().unwrap();
        let stale: Vec<u32> = map
            .keys()
            .filter_map(|k| k.ok())
            .filter(|pid| !live_pids.contains(pid))
            .collect();
        for pid in stale {
            let _ = map.remove(&pid);
        }
    }
}
