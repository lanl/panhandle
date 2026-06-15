// uses ebpf-based methods like tracepoints and kprobes to track per pid socket usage and states
use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{btf_tracepoint, kprobe, map},
    maps::HashMap,
    programs::{BtfTracePointContext, ProbeContext},
};
use panhandle_common::*;

// per pid hashmap for network stats
#[map(name = "net_stats")]
static mut NET_STATS: HashMap<u32, NetStats> = HashMap::with_max_entries(1024, 0);

// useful TCP states matching the struct in the kernel
const TCP_ESTABLISHED: i32 = 1;
const TCP_SYN_RECV: i32 = 3;
const TCP_FIN_WAIT1: i32 = 4;
const TCP_FIN_WAIT2: i32 = 5;
const TCP_TIME_WAIT: i32 = 6;
const TCP_CLOSE_WAIT: i32 = 8;

// helper macro for updating state counts
macro_rules! track_state {
    ($stats:expr, $field:ident, $oldstate:expr, $newstate:expr, $state:expr) => {
        // Entering this state
        if $newstate == $state {
            $stats.$field += 1;
        }
        // Exiting this state
        else if $oldstate == $state && $newstate != $state {
            if $stats.$field > 0 {
                $stats.$field -= 1;
            }
        }
    };
}

// TCP State tracking
#[btf_tracepoint(function = "inet_sock_set_state")]
pub fn inet_sock_set_state(ctx: BtfTracePointContext) -> u32 {
    let _ = try_inet_sock_set_state(ctx);
    0
}

fn try_inet_sock_set_state(ctx: BtfTracePointContext) -> Result<u32, u32> {
    let oldstate: i32 = unsafe { ctx.arg(1) };
    let newstate: i32 = unsafe { ctx.arg(2) };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let mut stats = unsafe { NET_STATS.get(&pid).copied().unwrap_or(NetStats::new()) };

    track_state!(stats, tcp_established, oldstate, newstate, TCP_ESTABLISHED);
    track_state!(stats, tcp_syn_recv, oldstate, newstate, TCP_SYN_RECV);
    track_state!(stats, tcp_close_wait, oldstate, newstate, TCP_CLOSE_WAIT);
    track_state!(stats, tcp_time_wait, oldstate, newstate, TCP_TIME_WAIT);
    track_state!(stats, tcp_fin_wait, oldstate, newstate, TCP_FIN_WAIT1);
    track_state!(stats, tcp_fin_wait, oldstate, newstate, TCP_FIN_WAIT2);

    let is_empty = stats.tcp_established == 0
        && stats.tcp_syn_recv == 0
        && stats.tcp_close_wait == 0
        && stats.tcp_time_wait == 0
        && stats.tcp_fin_wait == 0
        && stats.udp_sockets == 0;

    unsafe {
        if is_empty {
            if stats.bytes_sent == 0 && stats.bytes_recv == 0 {
                let _ = NET_STATS.remove(&pid);
            } else {
                let _ = NET_STATS.insert(&pid, &stats, 0);
            }
        } else {
            let _ = NET_STATS.insert(&pid, &stats, 0);
        }
    }

    Ok(0)
}

// TCP data sent - using kprobe
#[kprobe(function = "tcp_sendmsg")]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_sendmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_sendmsg(ctx: ProbeContext) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
    let size: usize = ctx.arg(2).ok_or(1u32)?;

    if size > 0 {
        let mut stats = unsafe { NET_STATS.get(&pid).copied().unwrap_or(NetStats::new()) };

        stats.bytes_sent += size as u64;
        stats.packets_sent += 1;

        unsafe {
            let _ = NET_STATS.insert(&pid, &stats, 0);
        }
    }

    Ok(0)
}

// TCP data received - using kprobe
#[kprobe(function = "tcp_cleanup_rbuf")]
pub fn tcp_cleanup_rbuf(ctx: ProbeContext) -> u32 {
    match try_tcp_cleanup_rbuf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_cleanup_rbuf(ctx: ProbeContext) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // tcp_cleanup_rbuf(struct sock *sk, int copied)
    let copied: i32 = ctx.arg(1).ok_or(1u32)?;

    if copied > 0 {
        let mut stats = unsafe { NET_STATS.get(&pid).copied().unwrap_or(NetStats::new()) };

        stats.bytes_recv += copied as u64;
        stats.packets_recv += 1;

        unsafe {
            let _ = NET_STATS.insert(&pid, &stats, 0);
        }
    }

    Ok(0)
}

// UDP data sent - using kprobe
#[kprobe(function = "udp_sendmsg")]
pub fn udp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_udp_sendmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_udp_sendmsg(ctx: ProbeContext) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
    let size: usize = ctx.arg(2).ok_or(1u32)?;

    let mut stats = unsafe { NET_STATS.get(&pid).copied().unwrap_or(NetStats::new()) };

    if stats.udp_sockets == 0 {
        stats.udp_sockets = 1; // since we don't have the luxury of checking set state, udp_sockets is more like a flag
    }

    if size > 0 {
        stats.bytes_sent += size as u64;
        stats.packets_sent += 1;
    }

    unsafe {
        let _ = NET_STATS.insert(&pid, &stats, 0);
    }

    Ok(0)
}

// UDP data received - using kprobe
#[kprobe(function = "udp_recvmsg")]
pub fn udp_recvmsg(ctx: ProbeContext) -> u32 {
    match try_udp_recvmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_udp_recvmsg(ctx: ProbeContext) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // int udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)
    let size: i32 = ctx.arg(2).ok_or(1u32)?;

    if size > 0 {
        let mut stats = unsafe { NET_STATS.get(&pid).copied().unwrap_or(NetStats::new()) };

        stats.bytes_recv += size as u64;
        stats.packets_recv += 1;

        unsafe {
            let _ = NET_STATS.insert(&pid, &stats, 0);
        }
    }

    Ok(0)
}
