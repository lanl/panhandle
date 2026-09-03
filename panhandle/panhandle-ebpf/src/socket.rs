// uses ebpf-based methods like tracepoints and kprobes to track per pid socket usage and states.
//
// Deliberately stateless: every probe below builds a small SocketStatsEvent delta and
// pushes it onto a ring buffer rather than doing a read-modify-write on a shared map.
// A prior version kept a per-pid NetStats HashMap here, updated via get -> mutate ->
// insert; that's not atomic across CPUs (concurrent updates for the same pid on
// different CPUs could race and lose an update), and entries were only evicted once
// all counters returned to zero, which never happens for a pid that has ever sent or
// received a byte -- on a long-running host the map filled permanently. Streaming
// deltas instead avoids both problems: there's no shared mutable state here to race
// on, and userspace (which already knows about process lifecycle) owns accumulation
// and cleanup in its own per-pid HashMap.
use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{btf_tracepoint, kprobe, map},
    maps::RingBuf,
    programs::{BtfTracePointContext, ProbeContext},
};
use aya_log_ebpf::warn;
use panhandle_common::SocketStatsEvent;

// Delta events for per-pid socket stats; folded into an accumulator on the userspace side.
#[map(name = "socket_events")]
static SOCKET_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 18, 0);

// useful TCP states matching the struct in the kernel
const TCP_ESTABLISHED: i32 = 1;
const TCP_SYN_RECV: i32 = 3;
const TCP_FIN_WAIT1: i32 = 4;
const TCP_FIN_WAIT2: i32 = 5;
const TCP_TIME_WAIT: i32 = 6;
const TCP_CLOSE_WAIT: i32 = 8;

// helper macro for computing a state-transition delta directly on the event (no
// shared/prior counter value needed - the kernel already tells us old and new state).
macro_rules! delta_for_state {
    ($event:expr, $field:ident, $oldstate:expr, $newstate:expr, $state:expr) => {
        // Entering this state
        if $newstate == $state {
            $event.$field += 1;
        }
        // Exiting this state
        else if $oldstate == $state && $newstate != $state {
            $event.$field -= 1;
        }
    };
}

// Reserve a ring buffer slot, write `event` into it, and submit. Returns false (and
// leaves it to the caller to warn, since each probe has a differently-typed context
// for aya_log_ebpf::warn!) if the ring buffer is full.
fn try_submit(event: SocketStatsEvent) -> bool {
    match SOCKET_EVENTS.reserve::<SocketStatsEvent>(0) {
        Some(mut entry) => {
            // SAFETY: freshly reserved, appropriately sized slot; write the whole event in one shot.
            unsafe {
                let ptr: *mut SocketStatsEvent = entry.as_mut_ptr();
                *ptr = event;
            }
            entry.submit(0);
            true
        }
        None => false,
    }
}

// TCP State tracking
#[btf_tracepoint(function = "inet_sock_set_state")]
pub fn inet_sock_set_state(ctx: BtfTracePointContext) -> u32 {
    let _ = try_inet_sock_set_state(ctx);
    0
}

fn try_inet_sock_set_state(ctx: BtfTracePointContext) -> Result<u32, u32> {
    let oldstate: i32 = ctx.arg(1);
    let newstate: i32 = ctx.arg(2);
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let mut event = SocketStatsEvent::new(pid);

    delta_for_state!(
        event,
        tcp_established_delta,
        oldstate,
        newstate,
        TCP_ESTABLISHED
    );
    delta_for_state!(event, tcp_syn_recv_delta, oldstate, newstate, TCP_SYN_RECV);
    delta_for_state!(
        event,
        tcp_close_wait_delta,
        oldstate,
        newstate,
        TCP_CLOSE_WAIT
    );
    delta_for_state!(
        event,
        tcp_time_wait_delta,
        oldstate,
        newstate,
        TCP_TIME_WAIT
    );
    delta_for_state!(event, tcp_fin_wait_delta, oldstate, newstate, TCP_FIN_WAIT1);
    delta_for_state!(event, tcp_fin_wait_delta, oldstate, newstate, TCP_FIN_WAIT2);

    if !try_submit(event) {
        warn!(
            &ctx,
            "socket_events ring buffer full, dropping update for pid {}", pid
        );
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
        let mut event = SocketStatsEvent::new(pid);
        event.bytes_sent_delta = size as u64;
        event.packets_sent_delta = 1;

        if !try_submit(event) {
            warn!(
                &ctx,
                "socket_events ring buffer full, dropping update for pid {}", pid
            );
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
        let mut event = SocketStatsEvent::new(pid);
        event.bytes_recv_delta = copied as u64;
        event.packets_recv_delta = 1;

        if !try_submit(event) {
            warn!(
                &ctx,
                "socket_events ring buffer full, dropping update for pid {}", pid
            );
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

    let mut event = SocketStatsEvent::new(pid);
    event.udp_sockets_set = 1; // since we don't have the luxury of checking set state, udp_sockets is more like a flag

    if size > 0 {
        event.bytes_sent_delta = size as u64;
        event.packets_sent_delta = 1;
    }

    if !try_submit(event) {
        warn!(
            &ctx,
            "socket_events ring buffer full, dropping update for pid {}", pid
        );
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
        let mut event = SocketStatsEvent::new(pid);
        event.bytes_recv_delta = size as u64;
        event.packets_recv_delta = 1;

        if !try_submit(event) {
            warn!(
                &ctx,
                "socket_events ring buffer full, dropping update for pid {}", pid
            );
        }
    }

    Ok(0)
}
