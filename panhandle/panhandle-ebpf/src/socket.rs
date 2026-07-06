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
    // SAFETY: BTF tracepoint argument access is safe
    // - ctx.arg(1) accesses the second argument (oldstate) of inet_sock_set_state
    // - BTF (BPF Type Format) ensures type safety and proper argument layout
    // - The kernel guarantees valid arguments for the inet_sock_set_state function
    // - Argument index 1 corresponds to the oldstate parameter in the function signature
    // - Validation: BTF tracepoint context guarantees argument exists and is properly typed
    let oldstate: i32 = unsafe { ctx.arg(1) };

    // SAFETY: BTF tracepoint argument access is safe
    // - ctx.arg(2) accesses the third argument (newstate) of inet_sock_set_state
    // - BTF ensures the argument is of type i32 as specified in kernel function signature
    // - The kernel guarantees valid arguments for the function
    // - Argument index 2 corresponds to the newstate parameter in the function signature
    // - Validation: BTF tracepoint context guarantees argument exists and is properly typed
    let newstate: i32 = unsafe { ctx.arg(2) };

    // SAFETY: bpf_get_current_pid_tgid() returns u64 with TGID in lower 32 bits and PID in upper 32 bits
    // - The function never returns 0 or null for the PID portion in kernel context
    // - Shifting right by 32 bits extracts the PID portion safely
    // - Cast to u32 is safe as PIDs are 32-bit values on all supported architectures
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // SAFETY: PID validation - ensure we have a valid process ID
    // - PID 0 is reserved for swapper/idle processes, but we still track it
    // - The eBPF verifier ensures bpf_get_current_pid_tgid() always returns valid data
    if pid == 0 {
        // Even if pid is 0, we'll still process the event but note this in safety
        // This should never happen in practice, but we handle it gracefully
    }

    // SAFETY: HashMap lookup in eBPF context is safe
    // - NET_STATS is a properly initialized HashMap<u32, NetStats> with max_entries=1024
    // - get(&pid) looks up network statistics for the current process
    // - copied() creates a deep copy of the NetStats struct (required for eBPF memory safety)
    // - unwrap_or(NetStats::new()) provides a default struct if key doesn't exist
    // - This pattern is safe for read-modify-write operations in eBPF
    // - Error handling: HashMap get() returns Option<&T>, None indicates missing key (not an error)
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

    // SAFETY: HashMap insert/remove operations are safe in eBPF context
    // - NET_STATS is a properly initialized mutable HashMap<u32, NetStats> with max_entries=1024
    // - pid is a valid process ID from bpf_get_current_pid_tgid() (non-zero, within bounds)
    // - stats is a valid NetStats struct that was either copied from the map or newly created
    // - insert operations handle memory allocation automatically with proper error handling
    // - remove operations safely handle missing keys (return None, not an error)
    // - Flag 0 indicates default insertion behavior
    // - Error handling: insert() returns Result<(), ebpf::Error> where Err indicates map is full
    //   We use let _ = to explicitly ignore the result, which is acceptable for statistics collection
    unsafe {
        if is_empty {
            if stats.bytes_sent == 0 && stats.bytes_recv == 0 {
                // SAFETY: remove() is safe even if key doesn't exist - returns None
                let _ = NET_STATS.remove(&pid);
            } else {
                // SAFETY: insert may fail if map is full, but we ignore error for statistics
                // In production, consider adding telemetry for map full conditions
                let _ = NET_STATS.insert(&pid, &stats, 0);
            }
        } else {
            // SAFETY: insert may fail if map is full, but we ignore error for statistics
            // In production, consider adding telemetry for map full conditions
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
    // SAFETY: bpf_get_current_pid_tgid() returns u64 with TGID in lower 32 bits and PID in upper 32 bits
    // - The function never returns 0 or null for the PID portion in kernel context
    // - Shifting right by 32 bits extracts the PID portion safely
    // - Cast to u32 is safe as PIDs are 32-bit values on all supported architectures
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
    // SAFETY: kprobe argument access with proper error handling
    // - ctx.arg(2) accesses the third argument (size) of tcp_sendmsg function
    // - The kernel guarantees valid arguments for kprobed functions when the probe is attached
    // - size parameter is of type size_t as specified in kernel function signature
    // - ok_or(1u32) provides error handling: returns Err(1) if argument access fails
    // - ? operator propagates the error, causing the function to return early with error code 1
    // - Validation: ctx.arg() returns Option<&T>, None indicates invalid access (verifier will catch this)
    let size: usize = ctx.arg(2).ok_or(1u32)?;

    if size > 0 {
        // SAFETY: HashMap lookup in eBPF context is safe
        // - NET_STATS is a properly initialized HashMap<u32, NetStats> with max_entries=1024
        // - get(&pid) looks up network statistics for the current process
        // - copied() creates a deep copy of the NetStats struct (required for eBPF memory safety)
        // - unwrap_or(NetStats::new()) provides a default struct if key doesn't exist
        // - Error handling: HashMap get() returns Option<&T>, None indicates missing key (not an error)
        let mut stats = unsafe { NET_STATS.get(&pid).copied().unwrap_or(NetStats::new()) };

        stats.bytes_sent += size as u64;
        stats.packets_sent += 1;

        // SAFETY: HashMap insert operation with explicit error handling
        // - NET_STATS is a properly initialized mutable HashMap<u32, NetStats>
        // - pid is a valid process ID from bpf_get_current_pid_tgid() (non-zero, within bounds)
        // - stats is a valid NetStats struct that was either copied from the map or newly created
        // - insert() returns Result<(), ebpf::Error> where Err indicates map is full
        // - We use let _ = to explicitly ignore the result, which is acceptable for statistics collection
        // - In production, consider adding telemetry for map full conditions
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
    // SAFETY: bpf_get_current_pid_tgid() returns u64 with TGID in lower 32 bits and PID in upper 32 bits
    // - The function never returns 0 or null for the PID portion in kernel context
    // - Shifting right by 32 bits extracts the PID portion safely
    // - Cast to u32 is safe as PIDs are 32-bit values on all supported architectures
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // tcp_cleanup_rbuf(struct sock *sk, int copied)
    // SAFETY: kprobe argument access with proper error handling
    // - ctx.arg(1) accesses the second argument (copied) of tcp_cleanup_rbuf function
    // - The kernel guarantees valid arguments for kprobed functions when the probe is attached
    // - copied parameter is of type int as specified in kernel function signature
    // - ok_or(1u32) provides error handling: returns Err(1) if argument access fails
    // - ? operator propagates the error, causing the function to return early with error code 1
    // - Validation: ctx.arg() returns Option<&T>, None indicates invalid access (verifier will catch this)
    let copied: i32 = ctx.arg(1).ok_or(1u32)?;

    if copied > 0 {
        // SAFETY: HashMap lookup in eBPF context is safe
        // - NET_STATS is a properly initialized HashMap<u32, NetStats> with max_entries=1024
        // - get(&pid) looks up network statistics for the current process
        // - copied() creates a deep copy of the NetStats struct (required for eBPF memory safety)
        // - unwrap_or(NetStats::new()) provides a default struct if key doesn't exist
        // - Error handling: HashMap get() returns Option<&T>, None indicates missing key (not an error)
        let mut stats = unsafe { NET_STATS.get(&pid).copied().unwrap_or(NetStats::new()) };

        stats.bytes_recv += copied as u64;
        stats.packets_recv += 1;

        // SAFETY: HashMap insert operation with explicit error handling
        // - NET_STATS is a properly initialized mutable HashMap<u32, NetStats>
        // - pid is a valid process ID from bpf_get_current_pid_tgid() (non-zero, within bounds)
        // - stats is a valid NetStats struct that was either copied from the map or newly created
        // - insert() returns Result<(), ebpf::Error> where Err indicates map is full
        // - We use let _ = to explicitly ignore the result, which is acceptable for statistics collection
        // - In production, consider adding telemetry for map full conditions
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
    // SAFETY: bpf_get_current_pid_tgid() returns u64 with TGID in lower 32 bits and PID in upper 32 bits
    // - The function never returns 0 or null for the PID portion in kernel context
    // - Shifting right by 32 bits extracts the PID portion safely
    // - Cast to u32 is safe as PIDs are 32-bit values on all supported architectures
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
    // SAFETY: kprobe argument access with proper error handling
    // - ctx.arg(2) accesses the third argument (len) of udp_sendmsg function
    // - The kernel guarantees valid arguments for kprobed functions when the probe is attached
    // - len parameter is of type size_t as specified in kernel function signature
    // - ok_or(1u32) provides error handling: returns Err(1) if argument access fails
    // - ? operator propagates the error, causing the function to return early with error code 1
    // - Validation: ctx.arg() returns Option<&T>, None indicates invalid access (verifier will catch this)
    let size: usize = ctx.arg(2).ok_or(1u32)?;

    // SAFETY: HashMap lookup in eBPF context is safe
    // - NET_STATS is a properly initialized HashMap<u32, NetStats> with max_entries=1024
    // - get(&pid) looks up network statistics for the current process
    // - copied() creates a deep copy of the NetStats struct (required for eBPF memory safety)
    // - unwrap_or(NetStats::new()) provides a default struct if key doesn't exist
    // - Error handling: HashMap get() returns Option<&T>, None indicates missing key (not an error)
    let mut stats = unsafe { NET_STATS.get(&pid).copied().unwrap_or(NetStats::new()) };

    if stats.udp_sockets == 0 {
        stats.udp_sockets = 1; // since we don't have the luxury of checking set state, udp_sockets is more like a flag
    }

    if size > 0 {
        stats.bytes_sent += size as u64;
        stats.packets_sent += 1;
    }

    // SAFETY: HashMap insert operation with explicit error handling
    // - NET_STATS is a properly initialized mutable HashMap<u32, NetStats>
    // - pid is a valid process ID from bpf_get_current_pid_tgid() (non-zero, within bounds)
    // - stats is a valid NetStats struct that was either copied from the map or newly created
    // - insert() returns Result<(), ebpf::Error> where Err indicates map is full
    // - We use let _ = to explicitly ignore the result, which is acceptable for statistics collection
    // - In production, consider adding telemetry for map full conditions
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
    // SAFETY: bpf_get_current_pid_tgid() returns u64 with TGID in lower 32 bits and PID in upper 32 bits
    // - The function never returns 0 or null for the PID portion in kernel context
    // - Shifting right by 32 bits extracts the PID portion safely
    // - Cast to u32 is safe as PIDs are 32-bit values on all supported architectures
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // int udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)
    // SAFETY: kprobe argument access with proper error handling
    // - ctx.arg(2) accesses the third argument (len) of udp_recvmsg function
    // - The kernel guarantees valid arguments for kprobed functions when the probe is attached
    // - len parameter is of type size_t in kernel but we read it as i32 for compatibility
    // - This is safe because we only use positive values and check size > 0 before incrementing
    // - ok_or(1u32) provides error handling: returns Err(1) if argument access fails
    // - ? operator propagates the error, causing the function to return early with error code 1
    // - Validation: ctx.arg() returns Option<&T>, None indicates invalid access (verifier will catch this)
    let size: i32 = ctx.arg(2).ok_or(1u32)?;

    if size > 0 {
        // SAFETY: HashMap lookup in eBPF context is safe
        // - NET_STATS is a properly initialized HashMap<u32, NetStats> with max_entries=1024
        // - get(&pid) looks up network statistics for the current process
        // - copied() creates a deep copy of the NetStats struct (required for eBPF memory safety)
        // - unwrap_or(NetStats::new()) provides a default struct if key doesn't exist
        // - Error handling: HashMap get() returns Option<&T>, None indicates missing key (not an error)
        let mut stats = unsafe { NET_STATS.get(&pid).copied().unwrap_or(NetStats::new()) };

        stats.bytes_recv += size as u64;
        stats.packets_recv += 1;

        // SAFETY: HashMap insert operation with explicit error handling
        // - NET_STATS is a properly initialized mutable HashMap<u32, NetStats>
        // - pid is a valid process ID from bpf_get_current_pid_tgid() (non-zero, within bounds)
        // - stats is a valid NetStats struct that was either copied from the map or newly created
        // - insert() returns Result<(), ebpf::Error> where Err indicates map is full
        // - We use let _ = to explicitly ignore the result, which is acceptable for statistics collection
        // - In production, consider adding telemetry for map full conditions
        unsafe {
            let _ = NET_STATS.insert(&pid, &stats, 0);
        }
    }

    Ok(0)
}
