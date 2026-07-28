use std::{convert::TryInto, sync::Arc};

use aya::maps::HashMap;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use panhandle_common::NetStats;
use procfs::process::Process;
use reqwest::Client;
use serde_json::json;

use crate::helpers::*;

/// Network monitoring main function
pub async fn monitor_network_usage(
    net_stats_map: &HashMap<aya::maps::MapData, u32, NetStats>,
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
    // Iterate over all entries in the map
    for (pid, stats) in net_stats_map.iter().flatten() {
        // Skip entries with no activity
        if !stats.has_activity() {
            continue;
        }

        // Get process information from procfs
        if let Ok(proc) = Process::new(pid.try_into().unwrap())
            && let Ok(stat) = proc.stat()
        {
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

            let (nic, ip, mac) = get_network_info(pid);

            // send all info to print function
            report_network_stats(
                pid,
                &stat.comm,
                ppid,
                parent_comm.as_deref(),
                &nic,
                &ip,
                &mac,
                &stats,
                &json_output,
                &http,
                &syslog,
                &debug,
                &verbose,
                hostname,
                syslog_address,
                global_url,
                client,
            )
            .await;
        }
    }
    Ok(())
}

// Format and output network statistics for a single process
async fn report_network_stats(
    pid: u32,
    comm: &str,
    ppid: Option<u32>,
    parent_comm: Option<&str>,
    nic: &str,
    ip: &str,
    mac: &str,
    stats: &NetStats,
    json_output: &&bool,
    http: &&bool,
    syslog: &&bool,
    debug_mode: &&bool,
    verbose: &&bool,
    hostname: &Arc<String>,
    syslog_address: &Arc<String>,
    http_url: &Arc<String>,
    client: &Client,
) {
    let bytes_sent_mb = stats.bytes_sent / (1024 * 1024);
    let bytes_recv_mb = stats.bytes_recv / (1024 * 1024);

    // Build messages conditionally based on verbose flag
    let (plain_string, json_string) = if **verbose {
        // Verbose mode: include parent info
        let ppid = ppid.unwrap_or(0);
        let parent_comm = parent_comm.unwrap_or("unknown");

        let plain = format!(
            "Type: sock, PID: {}, Comm: {}, PPID: {}, Parent_Comm: {}, NIC: {}, IP: {}, MAC: {}, ESTAB: {}, SYN_RECV: {}, CLOSE_WAIT: {}, FIN_WAIT: {}, TIME_WAIT: {}, UDP: {}, MB_Sent: {}, MB_Recv: {}, Packets_Sent: {}, Packets_Recv: {}",
            pid,
            comm,
            ppid,
            parent_comm,
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
        );

        let json_value = json!({
            "Type": "sock",
            "PID": pid,
            "Comm": comm,
            "PPID": ppid,
            "Parent_Comm": parent_comm,
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
        });

        (plain, json_value.to_string())
    } else {
        // Non-verbose mode: exclude parent info
        let plain = format!(
            "Type: sock, PID: {}, Comm: {}, NIC: {}, IP: {}, MAC: {}, ESTAB: {}, SYN_RECV: {}, CLOSE_WAIT: {}, FIN_WAIT: {}, TIME_WAIT: {}, UDP: {}, MB_Sent: {}, MB_Recv: {}, Packets_Sent: {}, Packets_Recv: {}",
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
        );

        let json_value = json!({
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
        });

        (plain, json_value.to_string())
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
fn get_network_info(pid: u32) -> (String, String, String) {
    // Get all interfaces once
    let interfaces = NetworkInterface::show().unwrap_or_default();

    // Try to match process connection to interface
    if let Some((iface_name, ip)) = get_active_connection_info(pid)
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
            return (iface.name, ip, mac);
        }
    }

    (
        "unknown".into(),
        "0.0.0.0".into(),
        "00:00:00:00:00:00".into(),
    )
}

// Get interface name and IP from process connections
fn get_active_connection_info(pid: u32) -> Option<(String, String)> {
    for path in [
        format!("/proc/{}/net/tcp", pid),
        format!("/proc/{}/net/tcp6", pid),
        format!("/proc/{}/net/udp", pid),
    ] {
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 2 {
                    continue;
                }

                if let Some(hex) = parts[1].split(':').next()
                    && let Some((iface, ip)) = hex_to_interface(hex)
                {
                    return Some((iface, ip));
                }
            }
        }
    }
    None
}

// Convert hex IP to interface name and IP string
fn hex_to_interface(hex: &str) -> Option<(String, String)> {
    let ip = if hex.len() == 8 {
        // IPv4
        let val = u32::from_str_radix(hex, 16).ok()?;
        let b = val.to_le_bytes();
        std::net::IpAddr::from([b[0], b[1], b[2], b[3]])
    } else {
        return None; // Skip IPv6 for simplicity
    };

    if ip.is_loopback() {
        return None;
    }

    // Match IP to interface
    let interfaces = NetworkInterface::show().ok()?;
    for iface in interfaces {
        for addr in iface.addr {
            if addr.ip() == ip {
                return Some((iface.name, ip.to_string()));
            }
        }
    }
    None
}
