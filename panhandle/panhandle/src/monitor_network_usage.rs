use std::{convert::TryInto, sync::Arc};

use aya::maps::HashMap;
use log::debug;
use network_interface::{NetworkInterface, NetworkInterfaceConfig}; // for getting nic information
use panhandle_common::NetStats;
use procfs::process::Process;
use reqwest::Client;
use serde_json::json;
use tokio::time::{Duration, sleep};

use crate::helpers::output_message;

/// Get process name from PID
fn get_process_name(pid: u32) -> Option<String> {
    Process::new(pid as i32)
        .ok()
        .and_then(|proc| proc.stat().ok())
        .map(|stat| stat.comm)
}

/// Network monitoring main function
/// This function runs continuously and reports network statistics for all processes
/// takes `net_stats_map` - eBPF map containing network statistics per PID
/// takes output formatting and location options (json, syslog, http)
pub async fn monitor_network_usage(
    net_stats_map: HashMap<aya::maps::MapData, u32, NetStats>,
    poll_interval: u32,
    json_output: bool,
    http: bool,
    syslog: bool,
    debug: bool,
    hostname: Arc<String>,
    syslog_address: Arc<String>,
    global_url: Arc<String>,
    client: Client,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        // Iterate over all entries in the map
        for item in net_stats_map.iter() {
            if let Ok((pid, stats)) = item {
                // Skip entries with no activity
                if !stats.has_activity() {
                    continue;
                }

                // Get process information from procfs
                if let Ok(proc) = Process::new(pid.try_into().unwrap())
                    && let Ok(stat) = proc.stat()
                {
                    // Get parent process pid and comm
                    let ppid = stat.ppid as u32;
                    let parent_comm = if ppid > 0 {
                        get_process_name(ppid).unwrap_or_else(|| "unknown".to_string())
                    } else {
                        "unknown".to_string()
                    };

                    let (nic, ip, mac) = get_network_info(pid);

                    // send all info to print function
                    report_network_stats(
                        pid,
                        &stat.comm,
                        ppid,
                        &parent_comm,
                        &nic,
                        &ip,
                        &mac,
                        &stats,
                        json_output,
                        http,
                        syslog,
                        debug,
                        &hostname,
                        &syslog_address,
                        &global_url,
                        &client,
                    )
                    .await;
                }
            }
        }

        sleep(Duration::from_secs(poll_interval.into())).await;
    }
}

// Format and output network statistics for a single process
async fn report_network_stats(
    pid: u32,
    comm: &str,
    ppid: u32,
    parent_comm: &str,
    nic: &str,
    ip: &str,
    mac: &str,
    stats: &NetStats,
    json_output: bool,
    http: bool,
    syslog: bool,
    debug_mode: bool,
    hostname: &Arc<String>,
    syslog_address: &Arc<String>,
    http_url: &Arc<String>,
    client: &Client,
) {
    // Plain text format
    let plain_string = format!(
        "PID: {}, Comm: {}, PPID: {}, Parent_Comm: {}, NIC: {}, IP: {}, MAC: {}, ESTAB:{}, SYN_RECV:{}, CLOSE_WAIT:{}, FIN_WAIT:{}, TIME_WAIT:{}, UDP:{}, Bytes_Sent:{}, Bytes_Recv:{}, Packets_Sent:{}, Packets_Recv:{}",
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
        stats.bytes_sent,
        stats.bytes_recv,
        stats.packets_sent,
        stats.packets_recv
    );

    // JSON format
    let json_value = json!({
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
        "Bytes_Sent": stats.bytes_sent,
        "Bytes_Recv": stats.bytes_recv,
        "Packets_Sent": stats.packets_sent,
        "Packets_Recv": stats.packets_recv,
    });

    let json_string = json_value.to_string();

    debug!("{}", plain_string);

    // Output via configured channels
    output_message(
        &http,
        &syslog,
        hostname,
        syslog_address,
        http_url,
        &json_output,
        &plain_string,
        &json_string,
        client,
        &debug_mode,
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

// Get interface name and IP from process connections. Read this info from procfs.
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
