use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use panhandle_common::{NetStats, SocketStatsEvent};
use procfs::process::{FDTarget, Process};
use reqwest::Client;
use serde_json::json;

use crate::helpers::*;

/// Per-pid socket stats accumulated from `SocketStatsEvent` deltas read off the
/// `socket_events` ring buffer (see `consume_socket_stats_ebpf_map` in helpers.rs).
/// Shared between that consumer task and the reporting loop in this module.
pub type SharedNetStats = Arc<Mutex<HashMap<u32, NetStats>>>;

/// Fold one delta event into the accumulated stats for its pid.
pub fn apply_socket_stats_event(net_stats: &SharedNetStats, event: &SocketStatsEvent) {
    let mut map = net_stats.lock().unwrap();
    let entry = map.entry(event.pid).or_default();
    entry.tcp_established = entry
        .tcp_established
        .saturating_add_signed(event.tcp_established_delta);
    entry.tcp_syn_recv = entry
        .tcp_syn_recv
        .saturating_add_signed(event.tcp_syn_recv_delta);
    entry.tcp_close_wait = entry
        .tcp_close_wait
        .saturating_add_signed(event.tcp_close_wait_delta);
    entry.tcp_time_wait = entry
        .tcp_time_wait
        .saturating_add_signed(event.tcp_time_wait_delta);
    entry.tcp_fin_wait = entry
        .tcp_fin_wait
        .saturating_add_signed(event.tcp_fin_wait_delta);
    if event.udp_sockets_set != 0 {
        entry.udp_sockets = entry.udp_sockets.max(1);
    }
    entry.bytes_sent += event.bytes_sent_delta;
    entry.bytes_recv += event.bytes_recv_delta;
    entry.packets_sent += event.packets_sent_delta;
    entry.packets_recv += event.packets_recv_delta;
}

// Fully-owned per-PID data gathered during the blocking scan phase, so the reporting
// loop afterward only needs to do async formatting/output work.
struct NetworkEntry {
    pid: u32,
    comm: String,
    ppid: Option<u32>,
    parent_comm: Option<String>,
    uid: Option<u32>,
    username: Option<String>,
    state: Option<char>,
    nic: String,
    ip: String,
    mac: String,
    stats: NetStats,
}

/// Plain-text rendering of a socket stats entry. `verbose` includes parent/owner/state
/// fields; the compact form keeps just PID/comm plus the socket counters.
pub fn format_socket_prose(
    verbose: bool,
    pid: u32,
    comm: &str,
    ppid: Option<u32>,
    parent_comm: Option<&str>,
    uid: Option<u32>,
    username: Option<&str>,
    state: Option<char>,
    nic: &str,
    ip: &str,
    mac: &str,
    stats: &NetStats,
    bytes_sent_mb: u64,
    bytes_recv_mb: u64,
) -> String {
    if verbose {
        let ppid_val = ppid.unwrap_or(0);
        let parent_comm_val = parent_comm.unwrap_or("unknown");
        let (uid_val, username_val) = format_owner(uid, username);
        let state_prose = format_state_prose(state);
        format!(
            "Type: sock, PID: {}, Comm: {}, Parent PID: {}, Parent Comm: {}, User ID: {}, User: {}, State: {}, NIC: {}, IP: {}, MAC: {}, Established: {}, Syn Recv: {}, Close Wait: {}, Fin Wait: {}, Time Wait: {}, UDP: {}, Sent: {} MB, Received: {} MB, Packets Sent: {}, Packets Received: {}",
            pid,
            comm,
            ppid_val,
            parent_comm_val,
            uid_val,
            username_val,
            state_prose,
            nic,
            ip,
            mac,
            stats.tcp_established,
            stats.tcp_syn_recv,
            stats.tcp_close_wait,
            stats.tcp_fin_wait,
            stats.tcp_time_wait,
            stats.udp_sockets,
            bytes_sent_mb,
            bytes_recv_mb,
            stats.packets_sent,
            stats.packets_recv
        )
    } else {
        format!(
            "Type: sock, PID: {}, Comm: {}, NIC: {}, IP: {}, MAC: {}, Established: {}, Syn Recv: {}, Close Wait: {}, Fin Wait: {}, Time Wait: {}, UDP: {}, Sent: {} MB, Received: {} MB, Packets Sent: {}, Packets Received: {}",
            pid,
            comm,
            nic,
            ip,
            mac,
            stats.tcp_established,
            stats.tcp_syn_recv,
            stats.tcp_close_wait,
            stats.tcp_fin_wait,
            stats.tcp_time_wait,
            stats.udp_sockets,
            bytes_sent_mb,
            bytes_recv_mb,
            stats.packets_sent,
            stats.packets_recv
        )
    }
}

/// JSON rendering of a socket stats entry, mirroring `format_socket_prose`. `verbose`
/// includes parent/owner/state fields; the compact form keeps just PID/comm plus the
/// socket counters. Built via the `json!` macro, so every string field is escaped by
/// serde_json and the document is always valid JSON.
pub fn format_socket_json(
    verbose: bool,
    pid: u32,
    comm: &str,
    ppid: Option<u32>,
    parent_comm: Option<&str>,
    uid: Option<u32>,
    username: Option<&str>,
    state: Option<char>,
    nic: &str,
    ip: &str,
    mac: &str,
    stats: &NetStats,
    bytes_sent_mb: u64,
    bytes_recv_mb: u64,
) -> String {
    if verbose {
        let ppid_val = ppid.unwrap_or(0);
        let parent_comm_val = parent_comm.unwrap_or("unknown");
        let (uid_val, username_val) = format_owner(uid, username);
        let state_val = format_state(state);
        json!({
            "Type": "sock",
            "PID": pid,
            "Comm": comm,
            "PPID": ppid_val,
            "Parent_Comm": parent_comm_val,
            "UID": uid_val,
            "Username": username_val,
            "State": state_val,
            "NIC": nic,
            "IP": ip,
            "MAC": mac,
            "ESTAB": stats.tcp_established,
            "SYN_RECV": stats.tcp_syn_recv,
            "CLOSE_WAIT": stats.tcp_close_wait,
            "FIN_WAIT": stats.tcp_fin_wait,
            "TIME_WAIT": stats.tcp_time_wait,
            "UDP": stats.udp_sockets,
            "MB_Sent": bytes_sent_mb,
            "MB_Recv": bytes_recv_mb,
            "Packets_Sent": stats.packets_sent,
            "Packets_Recv": stats.packets_recv,
        })
        .to_string()
    } else {
        json!({
            "Type": "sock",
            "PID": pid,
            "Comm": comm,
            "NIC": nic,
            "IP": ip,
            "MAC": mac,
            "ESTAB": stats.tcp_established,
            "SYN_RECV": stats.tcp_syn_recv,
            "CLOSE_WAIT": stats.tcp_close_wait,
            "FIN_WAIT": stats.tcp_fin_wait,
            "TIME_WAIT": stats.tcp_time_wait,
            "UDP": stats.udp_sockets,
            "MB_Sent": bytes_sent_mb,
            "MB_Recv": bytes_recv_mb,
            "Packets_Sent": stats.packets_sent,
            "Packets_Recv": stats.packets_recv,
        })
        .to_string()
    }
}

/// Remove entries for PIDs whose process no longer exists from the shared accumulator.
/// Without this, a pid that ever sent/received data would stay in `net_stats` forever,
/// growing it unboundedly on a long-running host - extracted so this eviction step is
/// independently testable without needing real procfs state to decide which pids are
/// "dead" (that determination is the caller's job; this just does the removal).
pub(crate) fn prune_dead_pids(net_stats: &SharedNetStats, dead_pids: Vec<u32>) {
    if dead_pids.is_empty() {
        return;
    }
    let mut map = net_stats.lock().unwrap();
    for pid in dead_pids {
        map.remove(&pid);
    }
}

/// Network monitoring main function
pub async fn monitor_network_usage(
    net_stats: &SharedNetStats,
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
    let (needs_plain, needs_json) = output_needs(*http, *syslog, *json_output, *debug);

    // Gather all procfs/netlink data up front (off the async executor) so the reporting
    // loop below only does formatting/output work, keeping blocking I/O off the shared
    // tokio worker threads for as short a window as possible.
    let entries: Vec<NetworkEntry> = tokio::task::block_in_place(|| {
        // Snapshot the accumulated stats without holding the lock during the procfs
        // scan below - the ring-buffer consumer task keeps folding new deltas into
        // this map concurrently, and we don't want to block it (or hold a lock across
        // blocking syscalls) for the whole scan.
        let snapshot: Vec<(u32, NetStats)> = {
            let map = net_stats.lock().unwrap();
            map.iter().map(|(&pid, &stats)| (pid, stats)).collect()
        };

        // Fetch the interface list once per poll cycle instead of once (or twice) per PID.
        let interfaces = NetworkInterface::show().unwrap_or_default();
        let mut entries = Vec::new();
        // PIDs whose process no longer exists, pruned from the accumulator below once
        // the scan is done. Without this, a pid that ever sent/received data would stay
        // in the map forever, growing it unboundedly on a long-running host.
        let mut dead_pids = Vec::new();
        // Cache of uid -> username, scoped to this single poll, so N processes owned by
        // the same user cost one username lookup instead of N when --verbose is set --
        // this can hit network-backed NSS (LDAP).
        let mut username_cache: HashMap<u32, String> = HashMap::new();

        for (pid, stats) in snapshot {
            // Skip entries with no activity
            if !stats.has_activity() {
                continue;
            }

            // Get process information from procfs
            let Ok(proc) = Process::new(pid.try_into().unwrap()) else {
                dead_pids.push(pid);
                continue;
            };
            let Ok(stat) = proc.stat() else {
                continue;
            };

            // apply PID filter if provided
            if let Some(pids) = pid_list
                && !pids.contains(&(stat.pid as u32))
            {
                continue;
            }

            // Only get parent info if verbose flag is set
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

            // Only get owner info if verbose flag is set
            let (uid, username, state) = if *verbose {
                let (uid, username) = match get_process_uid(pid) {
                    Some(uid) => {
                        let username = username_cache
                            .entry(uid)
                            .or_insert_with(|| resolve_username(uid))
                            .clone();
                        (Some(uid), Some(username))
                    }
                    None => (None, Some("unknown".to_string())),
                };
                (uid, username, Some(stat.state))
            } else {
                (None, None, None)
            };

            let (nic, ip, mac) = get_network_info(pid, &interfaces);

            entries.push(NetworkEntry {
                pid,
                comm: stat.comm,
                ppid,
                parent_comm,
                uid,
                username,
                state,
                nic,
                ip,
                mac,
                stats,
            });
        }

        prune_dead_pids(net_stats, dead_pids);

        entries
    });

    for entry in entries {
        // send all info to print function
        report_network_stats(
            entry.pid,
            &entry.comm,
            entry.ppid,
            entry.parent_comm.as_deref(),
            entry.uid,
            entry.username.as_deref(),
            entry.state,
            &entry.nic,
            &entry.ip,
            &entry.mac,
            &entry.stats,
            json_output,
            http,
            syslog,
            debug,
            verbose,
            needs_plain,
            needs_json,
            hostname,
            syslog_address,
            global_url,
            client,
        )
        .await;
    }
    Ok(())
}

// Format and output network statistics for a single process
async fn report_network_stats(
    pid: u32,
    comm: &str,
    ppid: Option<u32>,
    parent_comm: Option<&str>,
    uid: Option<u32>,
    username: Option<&str>,
    state: Option<char>,
    nic: &str,
    ip: &str,
    mac: &str,
    stats: &NetStats,
    json_output: &bool,
    http: &bool,
    syslog: &bool,
    debug_mode: &bool,
    verbose: &bool,
    needs_plain: bool,
    needs_json: bool,
    hostname: &Arc<String>,
    syslog_address: &Arc<String>,
    http_url: &Arc<String>,
    client: &Client,
) {
    let bytes_sent_mb = stats.bytes_sent / (1024 * 1024);
    let bytes_recv_mb = stats.bytes_recv / (1024 * 1024);

    // Build messages conditionally based on verbose flag
    let (plain_string, json_string) = if *verbose {
        // Verbose mode: include parent and owner info
        let plain = if needs_plain {
            format_socket_prose(
                true,
                pid,
                comm,
                ppid,
                parent_comm,
                uid,
                username,
                state,
                nic,
                ip,
                mac,
                stats,
                bytes_sent_mb,
                bytes_recv_mb,
            )
        } else {
            String::new()
        };

        let json_string = if needs_json {
            format_socket_json(
                true,
                pid,
                comm,
                ppid,
                parent_comm,
                uid,
                username,
                state,
                nic,
                ip,
                mac,
                stats,
                bytes_sent_mb,
                bytes_recv_mb,
            )
        } else {
            String::new()
        };

        (plain, json_string)
    } else {
        // Non-verbose mode: exclude parent info
        let plain = if needs_plain {
            format_socket_prose(
                false,
                pid,
                comm,
                ppid,
                parent_comm,
                uid,
                username,
                state,
                nic,
                ip,
                mac,
                stats,
                bytes_sent_mb,
                bytes_recv_mb,
            )
        } else {
            String::new()
        };

        let json_string = if needs_json {
            format_socket_json(
                false,
                pid,
                comm,
                ppid,
                parent_comm,
                uid,
                username,
                state,
                nic,
                ip,
                mac,
                stats,
                bytes_sent_mb,
                bytes_recv_mb,
            )
        } else {
            String::new()
        };

        (plain, json_string)
    };

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

// Get network info for a PID (interface, ip, mac)
pub(crate) fn get_network_info(
    pid: u32,
    interfaces: &[NetworkInterface],
) -> (String, String, String) {
    // Try to match process connection to interface
    if let Some((iface_name, ip)) = get_active_connection_info(pid, interfaces)
        && let Some(iface) = interfaces.iter().find(|i| i.name == iface_name)
    {
        let mac = iface
            .mac_addr
            .clone()
            .unwrap_or_else(|| "00:00:00:00:00:00".to_string());
        return (iface_name, ip, mac);
    }

    // Fallback: use default interface
    for iface in interfaces {
        if iface.name != "lo" && !iface.addr.is_empty() {
            let ip = iface.addr[0].ip().to_string();
            let mac = iface
                .mac_addr
                .clone()
                .unwrap_or_else(|| "00:00:00:00:00:00".to_string());
            return (iface.name.clone(), ip, mac);
        }
    }

    (
        "unknown".into(),
        "0.0.0.0".into(),
        "00:00:00:00:00:00".into(),
    )
}

// Get interface name and IP from process connections.
//
// /proc/<pid>/net/{tcp,tcp6,udp,udp6} reflect the whole network namespace, not
// sockets this specific pid owns - for the common case of processes sharing the
// default netns, every pid would see the exact same table. Cross-reference against
// this pid's own open file descriptors (/proc/<pid>/fd) to find which socket inodes
// actually belong to it, then only match those against the (shared) net tables.
pub(crate) fn get_active_connection_info(
    pid: u32,
    interfaces: &[NetworkInterface],
) -> Option<(String, String)> {
    let proc = Process::new(pid.try_into().ok()?).ok()?;

    let owned_inodes: HashSet<u64> = proc
        .fd()
        .ok()?
        .filter_map(|fd| fd.ok())
        .filter_map(|fd| match fd.target {
            FDTarget::Socket(inode) => Some(inode),
            _ => None,
        })
        .collect();

    if owned_inodes.is_empty() {
        return None;
    }

    let tcp_ips = proc
        .tcp()
        .unwrap_or_default()
        .into_iter()
        .chain(proc.tcp6().unwrap_or_default())
        .filter(|e| owned_inodes.contains(&e.inode))
        .map(|e| e.local_address.ip());
    let udp_ips = proc
        .udp()
        .unwrap_or_default()
        .into_iter()
        .chain(proc.udp6().unwrap_or_default())
        .filter(|e| owned_inodes.contains(&e.inode))
        .map(|e| e.local_address.ip());

    tcp_ips
        .chain(udp_ips)
        .filter(|ip| !ip.is_loopback())
        .find_map(|ip| ip_to_interface(ip, interfaces))
}

// Match an IP address (from either address family) to the interface that owns it.
pub(crate) fn ip_to_interface(
    ip: IpAddr,
    interfaces: &[NetworkInterface],
) -> Option<(String, String)> {
    for iface in interfaces {
        for addr in &iface.addr {
            if addr.ip() == ip {
                return Some((iface.name.clone(), ip.to_string()));
            }
        }
    }
    None
}
