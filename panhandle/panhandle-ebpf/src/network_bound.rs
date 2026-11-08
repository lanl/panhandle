use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{kprobe, kretprobe, map},
    maps::{HashMap, LruHashMap},
    programs::{ProbeContext, RetProbeContext},
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
// tcp_recvmsg - the kprobe/kretprobe pair always fires on that same thread), so two
// threads of the same process reading concurrently never clobber each other's start
// timestamp. NET_WAIT, on the other hand, is keyed by tgid (the process id as /proc
// and every other consumer in this codebase understands "pid") because that's the
// only key monitor_process_bounds.rs's procfs-driven lookup can use - keying it by
// thread id instead would silently lose every stat for a multi-threaded process
// whose network I/O doesn't happen to run on the thread-group leader.
#[kprobe]
pub fn tcp_recvmsg_entry(_ctx: ProbeContext) -> u32 {
    let thread_id = bpf_get_current_pid_tgid() as u32;
    unsafe {
        let ts = bpf_ktime_get_ns();
        START_TS.insert(&thread_id, &ts, 0).ok();
    }
    0
}

#[kretprobe]
pub fn tcp_recvmsg_exit(_ctx: RetProbeContext) -> u32 {
    let thread_id = bpf_get_current_pid_tgid() as u32;
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
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
    0
}
