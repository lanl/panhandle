use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{fentry, fexit, map},
    maps::{LruHashMap, RingBuf},
    programs::{FEntryContext, FExitContext},
};
use aya_log_ebpf::warn;
use panhandle_common::NetWaitEvent;

/// LRU HashMap for tracking TCP/UDP receive start timestamps, one per blocked thread.
/// Automatically evicts oldest entries when full, preventing leaks from missed exits
/// (e.g., process death, function not returning). Sized well above the number of
/// threads expected to be blocked in a receive at once: eviction drops the *oldest*
/// start time, i.e. the longest in-progress wait, so a too-small map would lose exactly
/// the waits that matter most. Fixed size (not per-CPU), roughly 1 MiB.
#[map]
static START_TS: LruHashMap<u32, u64> = LruHashMap::with_max_entries(16384, 0);

/// Completed-wait events, streamed to userspace rather than accumulated in a
/// kernel-side map - see `NetWaitEvent`'s doc comment for why (the same cross-CPU
/// lost-update race `socket.rs` was redesigned around). 1 MiB, independent of CPU
/// count: about 43k pending events (24 bytes each with the ring header) before the
/// userspace consumer has to catch up; a full ring drops the event with a warning.
#[map(name = "net_wait_events")]
static NET_WAIT_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

// START_TS is keyed by the raw pid_tgid value (the specific *thread* that entered
// tcp_recvmsg/udp_recvmsg - each fentry/fexit pair always fires on that same thread),
// so two threads of the same process reading concurrently never clobber each other's
// start timestamp; it's shared between the TCP and UDP probes below for the same
// reason - a single OS thread can only be blocked in one synchronous recvmsg call at
// a time, so entries from the two protocols can never collide on the same key.
//
// fentry/fexit (BTF trampolines) replace what used to be a kprobe/kretprobe pair:
// same timing logic, but attaching directly to the function instead of trapping on
// a breakpoint, which matters here - these run on every TCP/UDP receive.
fn record_recv_start(thread_id: u32) {
    unsafe {
        let ts = bpf_ktime_get_ns();
        START_TS.insert(&thread_id, &ts, 0).ok();
    }
}

// tgid (the process id as /proc and every other consumer in this codebase understands
// "pid") is what gets reported here, not thread_id - monitor_process_bounds.rs's
// procfs-driven lookup can only key by pid, and keying by thread id instead would
// silently lose every stat for a multi-threaded process whose network I/O doesn't
// happen to run on the thread-group leader. TCP and UDP wait time both report under
// the same pid, since "Network_Wait" is meant to be protocol-agnostic time spent
// waiting on any socket read; userspace folds both into one accumulator per process.
fn record_recv_elapsed(ctx: &FExitContext, thread_id: u32, tgid: u32) {
    unsafe {
        if let Some(&start) = START_TS.get(&thread_id) {
            let elapsed = bpf_ktime_get_ns() - start;
            match NET_WAIT_EVENTS.reserve::<NetWaitEvent>(0) {
                Some(mut entry) => {
                    let ptr: *mut NetWaitEvent = entry.as_mut_ptr();
                    *ptr = NetWaitEvent::new(tgid, elapsed);
                    entry.submit(0);
                }
                None => warn!(
                    ctx,
                    "net_wait_events ring buffer full, dropping network wait for pid {}", tgid
                ),
            }
            START_TS.remove(&thread_id).ok();
        }
    }
}

#[fentry(function = "tcp_recvmsg")]
pub fn tcp_recvmsg_entry(_ctx: FEntryContext) -> u32 {
    record_recv_start(bpf_get_current_pid_tgid() as u32);
    0
}

#[fexit(function = "tcp_recvmsg")]
pub fn tcp_recvmsg_exit(ctx: FExitContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    record_recv_elapsed(&ctx, pid_tgid as u32, (pid_tgid >> 32) as u32);
    0
}

#[fentry(function = "udp_recvmsg")]
pub fn udp_recvmsg_entry(_ctx: FEntryContext) -> u32 {
    record_recv_start(bpf_get_current_pid_tgid() as u32);
    0
}

#[fexit(function = "udp_recvmsg")]
pub fn udp_recvmsg_exit(ctx: FExitContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    record_recv_elapsed(&ctx, pid_tgid as u32, (pid_tgid >> 32) as u32);
    0
}
