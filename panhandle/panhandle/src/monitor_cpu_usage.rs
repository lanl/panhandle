use std::collections::{HashMap, HashSet};

use procfs::{
    CurrentSI,
    process::{Process, Stat, all_processes},
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
pub(crate) struct CpuEntry {
    pid: u32,
    comm: String,
    found: bool,
    ppid: Option<u32>,
    parent_comm: Option<String>,
    uid: Option<u32>,
    username: Option<String>,
    state: Option<char>,
    pub(crate) cpu_time: u64,
    pub(crate) delta: u64,
    pub(crate) cpu_percent: f64,
    pub(crate) avg_cpu_percent: f64,
    pub(crate) max_cpu_percent: f64,
}

/// Plain-text rendering of a found CPU entry. `verbose` includes parent/owner/state and
/// timing fields; the compact form keeps just PID/comm plus the CPU percentages.
pub fn format_cpu_prose(
    verbose: bool,
    pid: u32,
    comm: &str,
    ppid: Option<u32>,
    parent_comm: Option<&str>,
    uid: Option<u32>,
    username: Option<&str>,
    state: Option<char>,
    cpu_time_ms: f64,
    delta_ms: f64,
    cpu_percent: f64,
    avg_cpu_percent: f64,
    max_cpu_percent: f64,
) -> String {
    if verbose {
        let ppid_val = ppid.unwrap_or(0);
        let parent_comm_val = parent_comm.unwrap_or("unknown");
        let (uid_val, username_val) = format_owner(uid, username);
        let state_prose = format_state_prose(state);
        format!(
            "Type: cpu, PID: {}, Comm: {}, Parent PID: {}, Parent Comm: {}, User ID: {}, User: {}, State: {}, Total Time: {:.2} ms, Delta Time: {:.2} ms, CPU: {:.2}%, Avg CPU: {:.2}%, Max CPU: {:.2}%",
            pid,
            comm,
            ppid_val,
            parent_comm_val,
            uid_val,
            username_val,
            state_prose,
            cpu_time_ms,
            delta_ms,
            cpu_percent,
            avg_cpu_percent,
            max_cpu_percent
        )
    } else {
        format!(
            "Type: cpu, PID: {}, Comm: {}, CPU: {:.2}%, Avg CPU: {:.2}%, Max CPU: {:.2}%",
            pid, comm, cpu_percent, avg_cpu_percent, max_cpu_percent
        )
    }
}

/// Plain-text rendering of a process that disappeared between the scan and report phases.
pub fn format_cpu_not_found_prose(
    verbose: bool,
    pid: u32,
    comm: &str,
    ppid: Option<u32>,
    parent_comm: Option<&str>,
    uid: Option<u32>,
    username: Option<&str>,
) -> String {
    if verbose {
        let ppid_val = ppid.unwrap_or(0);
        let parent_comm_val = parent_comm.unwrap_or("unknown");
        let (uid_val, username_val) = format_owner(uid, username);
        format!(
            "Type: cpu, PID: {}, Comm: {}, Parent PID: {}, Parent Comm: {}, User ID: {}, User: {}, Status: not_found",
            pid, comm, ppid_val, parent_comm_val, uid_val, username_val
        )
    } else {
        format!("Type: cpu, PID: {}, Comm: {}, Status: not_found", pid, comm)
    }
}

/// JSON rendering of a found CPU entry, mirroring `format_cpu_prose`. `verbose` includes
/// parent/owner/state and timing fields; the compact form keeps just PID/comm plus the
/// CPU percentages. All string fields are escaped via `json_quoted` so the document is
/// always valid JSON even if a comm or username contains quotes or control characters.
pub fn format_cpu_json(
    verbose: bool,
    pid: u32,
    comm: &str,
    ppid: Option<u32>,
    parent_comm: Option<&str>,
    uid: Option<u32>,
    username: Option<&str>,
    state: Option<char>,
    cpu_time_ms: f64,
    delta_ms: f64,
    cpu_percent: f64,
    avg_cpu_percent: f64,
    max_cpu_percent: f64,
) -> String {
    if verbose {
        let ppid_val = ppid.unwrap_or(0);
        let parent_comm_val = parent_comm.unwrap_or("unknown");
        let (uid_val, username_val) = format_owner(uid, username);
        let state_val = format_state(state);
        format!(
            "{{\"Type\": \"cpu\", \"PID\": {}, \"Comm\": {}, \"PPID\": {}, \"Parent_Comm\": {}, \"UID\": {}, \"Username\": {}, \"State\": {}, \"Total_Time_ms\": {:.2}, \"Delta_Time_ms\": {:.2}, \"CPU%\": {:.2}, \"Avg_CPU%\": {:.2}, \"Max_CPU%\": {:.2}}}",
            pid,
            json_quoted(comm),
            ppid_val,
            json_quoted(parent_comm_val),
            json_quoted(&uid_val),
            json_quoted(&username_val),
            json_quoted(&state_val),
            cpu_time_ms,
            delta_ms,
            cpu_percent,
            avg_cpu_percent,
            max_cpu_percent
        )
    } else {
        format!(
            "{{\"Type\": \"cpu\", \"PID\": {}, \"Comm\": {}, \"CPU%\": {:.2}, \"Avg_CPU%\": {:.2}, \"Max_CPU%\": {:.2}}}",
            pid,
            json_quoted(comm),
            cpu_percent,
            avg_cpu_percent,
            max_cpu_percent
        )
    }
}

/// JSON rendering of a process that disappeared between the scan and report phases,
/// mirroring `format_cpu_not_found_prose`. All string fields are escaped via
/// `json_quoted` so the document is always valid JSON.
pub fn format_cpu_not_found_json(
    verbose: bool,
    pid: u32,
    comm: &str,
    ppid: Option<u32>,
    parent_comm: Option<&str>,
    uid: Option<u32>,
    username: Option<&str>,
) -> String {
    if verbose {
        let ppid_val = ppid.unwrap_or(0);
        let parent_comm_val = parent_comm.unwrap_or("unknown");
        let (uid_val, username_val) = format_owner(uid, username);
        format!(
            "{{\"Type\": \"cpu\", \"PID\": {}, \"Comm\": {}, \"PPID\": {}, \"Parent_Comm\": {}, \"UID\": {}, \"Username\": {}, \"Status\": \"not_found\"}}",
            pid,
            json_quoted(comm),
            ppid_val,
            json_quoted(parent_comm_val),
            json_quoted(&uid_val),
            json_quoted(&username_val)
        )
    } else {
        format!(
            "{{\"Type\": \"cpu\", \"PID\": {}, \"Comm\": {}, \"Status\": \"not_found\"}}",
            pid,
            json_quoted(comm)
        )
    }
}

/// Plain-text rendering of the system-wide CPU% summary line, mirroring
/// `format_system_cpu_json`.
pub fn format_system_cpu_prose(
    system_cpu_percent: f64,
    num_cpus: usize,
    busy_delta_ms: f64,
) -> String {
    format!(
        "Type: cpu, CPU: {:.2}%, CPUs: {}, Busy Delta: {:.2} ms",
        system_cpu_percent, num_cpus, busy_delta_ms
    )
}

/// JSON rendering of the system-wide CPU% summary line. All values are numeric, so no
/// string escaping is needed.
pub fn format_system_cpu_json(
    system_cpu_percent: f64,
    num_cpus: usize,
    busy_delta_ms: f64,
) -> String {
    format!(
        "{{\"Type\": \"cpu\", \"CPU%\": {:.2}, \"Num_CPUs\": {}, \"Busy_Delta_ms\": {:.2}}}",
        system_cpu_percent, num_cpus, busy_delta_ms
    )
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
    last_total_busy: &mut Option<u64>,
    last_pid_times: &mut HashMap<u32, u64>,
    pid_stats: &mut HashMap<u32, PidStats>,
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

            // Cache of ppid -> parent comm, scoped to this single poll, so N children of
            // the same parent (common: many children of one shell/container-init) cost
            // one /proc/<ppid>/stat read instead of N when --verbose is set.
            let mut parent_comm_cache: HashMap<u32, String> = HashMap::new();
            let resolve_parent = |pid: u32,
                                  cache: &mut HashMap<u32, String>|
             -> (Option<u32>, Option<String>) {
                if let Ok(parent_pid) = get_parent_pid(pid) {
                    let parent_name = cache
                        .entry(parent_pid)
                        .or_insert_with(|| {
                            get_process_name(parent_pid).unwrap_or_else(|| "unknown".to_string())
                        })
                        .clone();
                    (Some(parent_pid), Some(parent_name))
                } else {
                    (Some(0), Some("unknown".to_string()))
                }
            };

            // Cache of uid -> username, scoped to this single poll, so N processes owned
            // by the same user (the common case) cost one username lookup instead of N
            // when --verbose is set -- this can hit network-backed NSS (LDAP).
            let mut username_cache: HashMap<u32, String> = HashMap::new();
            let resolve_owner =
                |pid: u32, cache: &mut HashMap<u32, String>| -> (Option<u32>, Option<String>) {
                    match get_process_uid(pid) {
                        Some(uid) => {
                            let username = cache
                                .entry(uid)
                                .or_insert_with(|| resolve_username(uid))
                                .clone();
                            (Some(uid), Some(username))
                        }
                        None => (None, Some("unknown".to_string())),
                    }
                };

            let mut entries = Vec::new();

            if let Some(filter) = pid_filter {
                // Prune tracking state for PIDs no longer in the filter, so these maps
                // don't grow unbounded and a reused PID doesn't inherit stale stats.
                let live_pids: HashSet<u32> = filter.iter().copied().collect();
                last_pid_times.retain(|pid, _| live_pids.contains(pid));
                pid_stats.retain(|pid, _| live_pids.contains(pid));

                for &pid in filter {
                    if let Ok(proc) = Process::new(pid as i32)
                        && let Ok(stat) = proc.stat()
                    {
                        let (ppid, parent_comm) = if *verbose {
                            resolve_parent(pid, &mut parent_comm_cache)
                        } else {
                            (None, None)
                        };
                        let (uid, username) = if *verbose {
                            resolve_owner(pid, &mut username_cache)
                        } else {
                            (None, None)
                        };
                        let state = if *verbose { Some(stat.state) } else { None };
                        let mut entry = build_found_entry(
                            pid,
                            stat,
                            ppid,
                            parent_comm,
                            ticks_per_second,
                            interval_ns,
                            last_pid_times,
                            pid_stats,
                        );
                        entry.uid = uid;
                        entry.username = username;
                        entry.state = state;
                        entries.push(entry);
                    } else {
                        let (ppid, parent_comm) = if *verbose {
                            resolve_parent(pid, &mut parent_comm_cache)
                        } else {
                            (None, None)
                        };
                        let (uid, username) = if *verbose {
                            resolve_owner(pid, &mut username_cache)
                        } else {
                            (None, None)
                        };
                        entries.push(CpuEntry {
                            pid,
                            comm: "unknown".to_string(),
                            found: false,
                            ppid,
                            parent_comm,
                            uid,
                            username,
                            state: None,
                            cpu_time: 0,
                            delta: 0,
                            cpu_percent: 0.0,
                            avg_cpu_percent: 0.0,
                            max_cpu_percent: 0.0,
                        });
                    }
                }
            } else {
                // Use the Process handles all_processes() already opened instead of
                // discarding them to bare PIDs and reopening via Process::new() below.
                let procs: Vec<Process> = all_processes()
                    .map(|procs| procs.flatten().collect())
                    .unwrap_or_default();

                let live_pids: HashSet<u32> = procs.iter().map(|p| p.pid() as u32).collect();
                last_pid_times.retain(|pid, _| live_pids.contains(pid));
                pid_stats.retain(|pid, _| live_pids.contains(pid));

                for proc in procs {
                    let pid = proc.pid() as u32;
                    // Without a --pid-list filter, a PID that vanished between being
                    // listed and being read here is silently skipped rather than
                    // reported not_found, matching the filtered path's intent (only
                    // explicitly-requested PIDs get a not_found report).
                    if let Ok(stat) = proc.stat() {
                        let (ppid, parent_comm) = if *verbose {
                            resolve_parent(pid, &mut parent_comm_cache)
                        } else {
                            (None, None)
                        };
                        let (uid, username) = if *verbose {
                            resolve_owner(pid, &mut username_cache)
                        } else {
                            (None, None)
                        };
                        let state = if *verbose { Some(stat.state) } else { None };
                        let mut entry = build_found_entry(
                            pid,
                            stat,
                            ppid,
                            parent_comm,
                            ticks_per_second,
                            interval_ns,
                            last_pid_times,
                            pid_stats,
                        );
                        entry.uid = uid;
                        entry.username = username;
                        entry.state = state;
                        entries.push(entry);
                    }
                }
            }

            (entries, total_busy, num_cpus)
        });

    for entry in entries {
        if entry.found {
            // Build messages conditionally based on verbose flag
            let plain_string = if needs_plain {
                format_cpu_prose(
                    *verbose,
                    entry.pid,
                    &entry.comm,
                    entry.ppid,
                    entry.parent_comm.as_deref(),
                    entry.uid,
                    entry.username.as_deref(),
                    entry.state,
                    entry.cpu_time as f64 / 1_000_000.0,
                    entry.delta as f64 / 1_000_000.0,
                    entry.cpu_percent,
                    entry.avg_cpu_percent,
                    entry.max_cpu_percent,
                )
            } else {
                String::new()
            };

            let json_string = if needs_json {
                format_cpu_json(
                    *verbose,
                    entry.pid,
                    &entry.comm,
                    entry.ppid,
                    entry.parent_comm.as_deref(),
                    entry.uid,
                    entry.username.as_deref(),
                    entry.state,
                    entry.cpu_time as f64 / 1_000_000.0,
                    entry.delta as f64 / 1_000_000.0,
                    entry.cpu_percent,
                    entry.avg_cpu_percent,
                    entry.max_cpu_percent,
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
        } else {
            let plain_string = if needs_plain {
                format_cpu_not_found_prose(
                    *verbose,
                    entry.pid,
                    &entry.comm,
                    entry.ppid,
                    entry.parent_comm.as_deref(),
                    entry.uid,
                    entry.username.as_deref(),
                )
            } else {
                String::new()
            };
            let json_string = if needs_json {
                format_cpu_not_found_json(
                    *verbose,
                    entry.pid,
                    &entry.comm,
                    entry.ppid,
                    entry.parent_comm.as_deref(),
                    entry.uid,
                    entry.username.as_deref(),
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
    }

    // System-wide CPU%: busy time accumulated across all cores since the last poll,
    // normalized to 0-100% (100% = every core fully busy), matching the convention
    // used by tools like top/htop's summary line rather than this file's per-PID
    // "100% = one core" scale. last_total_busy is only updated here, inside the
    // success guard, so a failed KernelStats read (num_cpus == 0) never poisons the
    // baseline with a fabricated "observed as zero" value.
    if num_cpus > 0 {
        let busy_delta = calc_delta(total_busy, *last_total_busy);
        *last_total_busy = Some(total_busy);
        let system_cpu_percent = calc_system_cpu_percent(busy_delta, interval_ns, num_cpus);

        let plain_string = if needs_plain {
            format_system_cpu_prose(
                system_cpu_percent,
                num_cpus,
                busy_delta as f64 / 1_000_000.0,
            )
        } else {
            String::new()
        };
        let json_string = if needs_json {
            format_system_cpu_json(
                system_cpu_percent,
                num_cpus,
                busy_delta as f64 / 1_000_000.0,
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

    Ok(())
}

/// Build a CpuEntry for a successfully-read PID, updating the per-PID delta/average/max
/// tracking state as a side effect. Shared by both the --pid-list-filtered and
/// all-processes gather paths so the accounting logic isn't duplicated between them.
pub(crate) fn build_found_entry(
    pid: u32,
    stat: Stat,
    ppid: Option<u32>,
    parent_comm: Option<String>,
    ticks_per_second: u64,
    interval_ns: u64,
    last_pid_times: &mut HashMap<u32, u64>,
    pid_stats: &mut HashMap<u32, PidStats>,
) -> CpuEntry {
    let cpu_time = (stat.utime + stat.stime) * 1_000_000_000 / ticks_per_second;
    let delta = calc_delta(cpu_time, last_pid_times.get(&pid).copied());
    let cpu_percent = calc_cpu_percent(delta, interval_ns);

    let stats = pid_stats.entry(pid).or_default();
    stats.total_time = cpu_time;
    stats.sample_count += 1;
    stats.max_cpu_percent = stats.max_cpu_percent.max(cpu_percent);
    stats.avg_cpu_percent = (stats.avg_cpu_percent * (stats.sample_count - 1) as f64 + cpu_percent)
        / stats.sample_count as f64;
    let avg_cpu_percent = stats.avg_cpu_percent;
    let max_cpu_percent = stats.max_cpu_percent;

    last_pid_times.insert(pid, cpu_time);

    CpuEntry {
        pid,
        comm: stat.comm,
        found: true,
        ppid,
        parent_comm,
        // set by the caller, which has access to *verbose without threading it through
        // this already-8-argument helper
        uid: None,
        username: None,
        state: None,
        cpu_time,
        delta,
        cpu_percent,
        avg_cpu_percent,
        max_cpu_percent,
    }
}
