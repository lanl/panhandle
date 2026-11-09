use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{fentry, fexit, map},
    maps::{HashMap, LruHashMap},
    programs::{FEntryContext, FExitContext},
};

/// LRU HashMap for tracking TCP receive start timestamps.
/// Automatically evicts oldest entries when full, preventing leaks from kretprobe misses
/// (e.g., process death, function not returning).
#[map]
static START_TS: LruHashMap<u32, u64> = LruHashMap::with_max_entries(1024, 0);

#[map]
static NET_WAIT: HashMap<u32, NetWaitStat> = HashMap::with_max_entries(1024, 0);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetWaitStat {
    pub count: u64,
    pub total_ns: u64,
}

// START_TS is keyed by the raw pid_tgid value (the specific *thread* that entered
// tcp_recvmsg/udp_recvmsg - each fentry/fexit pair always fires on that same thread),
// so two threads of the same process reading concurrently never clobber each other's
// start timestamp; it's shared between the TCP and UDP probes below for the same
// reason - a single OS thread can only be blocked in one synchronous recvmsg call at
// a time, so entries from the two protocols can never collide on the same key.
// NET_WAIT, on the other hand, is keyed by tgid (the process id as /proc and every
// other consumer in this codebase understands "pid") because that's the only key
// monitor_process_bounds.rs's procfs-driven lookup can use - keying it by thread id
// instead would silently lose every stat for a multi-threaded process whose network
// I/O doesn't happen to run on the thread-group leader. TCP and UDP wait time both
// fold into the same NET_WAIT entry per process, since "Network_Wait" is meant to be
// protocol-agnostic time spent waiting on any socket read.
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

fn record_recv_elapsed(thread_id: u32, tgid: u32) {
    unsafe {
        if let Some(&start) = START_TS.get(&thread_id) {
            let elapsed = bpf_ktime_get_ns() - start;
            let mut stat = NET_WAIT.get(&tgid).copied().unwrap_or(NetWaitStat {
                count: 0,
                total_ns: 0,
            });
            stat.count += 1;
            stat.total_ns += elapsed;
            NET_WAIT.insert(&tgid, &stat, 0).ok();
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
pub fn tcp_recvmsg_exit(_ctx: FExitContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    record_recv_elapsed(pid_tgid as u32, (pid_tgid >> 32) as u32);
    0
}

#[fentry(function = "udp_recvmsg")]
pub fn udp_recvmsg_entry(_ctx: FEntryContext) -> u32 {
    record_recv_start(bpf_get_current_pid_tgid() as u32);
    0
}

#[fexit(function = "udp_recvmsg")]
pub fn udp_recvmsg_exit(_ctx: FExitContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    record_recv_elapsed(pid_tgid as u32, (pid_tgid >> 32) as u32);
    0
}
