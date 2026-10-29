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

#[kprobe]
pub fn tcp_recvmsg_entry(_ctx: ProbeContext) -> u32 {
    let pid = bpf_get_current_pid_tgid() as u32;
    unsafe {
        let ts = bpf_ktime_get_ns();
        START_TS.insert(&pid, &ts, 0).ok();
    }
    0
}

#[kretprobe]
pub fn tcp_recvmsg_exit(_ctx: RetProbeContext) -> u32 {
    let pid = bpf_get_current_pid_tgid() as u32;
    unsafe {
        if let Some(&start) = START_TS.get(&pid) {
            let elapsed = bpf_ktime_get_ns() - start;
            let mut stat = NET_WAIT.get(&pid).copied().unwrap_or(NetWaitStat {
                count: 0,
                total_ns: 0,
            });
            stat.count += 1;
            stat.total_ns += elapsed;
            NET_WAIT.insert(&pid, &stat, 0).ok();
            START_TS.remove(&pid).ok();
        }
    }
    0
}
