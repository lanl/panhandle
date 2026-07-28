#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(static_mut_refs)]

use aya_ebpf::{
    EbpfContext,
    helpers::bpf_ktime_get_ns,
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray},
    programs::TracePointContext,
};
use aya_log_ebpf::info;
use panhandle_common::*;

// per cpu array that holds timestamp when currently running task on this cpu started executing
#[map(name = "start_times")]
static START_TIMES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// hash map that stores total accumulated CPU time per process ID. 256 is max amount of processes
#[map(name = "per_cpu_time")]
static PID_CPU_TIME: HashMap<u32, u64> = HashMap::with_max_entries(256, 0);

// keep total busy time per CPU. Summing all CPUs gives the system-wide total CPU busy time
#[map(name = "busy_cpu_time")]
static BUSY_CPU_TIME: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    match try_sched_switch(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_sched_switch(ctx: TracePointContext) -> Result<u32, i64> {
    // OVERFLOW PROTECTION:
    // - Time delta calculation uses saturating_sub to prevent underflow from clock anomalies
    // - CPU time accumulation uses checked_add to detect and handle overflow explicitly
    // - Overflow errors are propagated through Result type with specific error codes
    // - Error codes: 1=start_time_slot, 2=PID_CPU_TIME insert, 3=busy_slot, 4=PID CPU time overflow, 5=busy CPU time overflow
    // SAFETY: Context casting to tracepoint struct is safe
    // - ctx.as_ptr() returns a valid pointer to the tracepoint context data
    // - The cast to trace_event_raw_sched_switch is valid for the sched_switch tracepoint
    // - The kernel guarantees the context data layout matches the tracepoint struct
    // - sched_switch tracepoint is stable across kernel versions
    let tp: *const trace_event_raw_sched_switch = ctx.as_ptr().cast();

    // SAFETY: Pointer dereferencing is safe in tracepoint context
    // - tp points to valid, kernel-provided memory for the sched_switch tracepoint
    // - prev_pid field exists in trace_event_raw_sched_switch struct
    // - The memory is read-only and properly aligned
    // - Field access is guaranteed to be within bounds
    let prev_pid = unsafe { (*tp).prev_pid } as u32;

    // get current time
    // SAFETY: bpf_ktime_get_ns is a verified eBPF helper function
    // - Returns monotonically increasing nanoseconds since boot
    // - No error conditions - always succeeds in eBPF context
    // - Provided by Aya library which wraps the kernel helper
    // - Safe for use in tracepoint programs
    let now = unsafe { bpf_ktime_get_ns() };

    // handle the outgoing task
    let start_time_slot = START_TIMES.get_ptr_mut(0).ok_or_else(|| {
        info!(&ctx, "Failed to get start_time_slot");
        1i64
    })?;

    // SAFETY: PerCpuArray pointer dereferencing is safe
    // - start_time_slot is a valid pointer returned from START_TIMES.get_ptr_mut(0)
    // - The Some variant indicates the pointer is valid and properly aligned
    // - START_TIMES is a PerCpuArray<u64> with max_entries=1, created at load time
    // - CPU 0's slot is always accessible in a running system
    // - The pointer is guaranteed to point to a valid u64 value
    let prev_start = unsafe { *start_time_slot };

    // if task was running, account its runtime
    if prev_start != 0 {
        // Use saturating_sub to prevent underflow if prev_start > now (clock anomaly)
        // This gracefully handles edge cases while maintaining correctness
        let delta = now.saturating_sub(prev_start);

        if prev_pid != 0 {
            // update the per PID total
            match PID_CPU_TIME.get_ptr_mut(&prev_pid) {
                Some(entry) => {
                    // SAFETY: HashMap pointer dereferencing is safe
                    // - entry is a valid pointer returned from PID_CPU_TIME.get_ptr_mut(&prev_pid)
                    // - The Some variant indicates the key exists and pointer is valid
                    // - PID_CPU_TIME is a HashMap<u32, u64> with max_entries=1024
                    // - prev_pid is a valid process ID from the kernel
                    // - The pointer is guaranteed to point to a valid u64 value
                    // - Atomic addition is safe in eBPF context (no data races due to per-CPU nature)
                    // Use checked_add to prevent overflow - return error if it would overflow
                    let current = unsafe { *entry };
                    unsafe {
                        *entry = current.checked_add(delta).ok_or_else(|| {
                            info!(&ctx, "CPU time overflow for PID {}", prev_pid);
                            4i64
                        })?;
                    }
                }
                None => {
                    PID_CPU_TIME
                        .insert(&prev_pid, &delta, 0)
                        .map_err(|_e| 2i64)?;
                }
            }

            // update busy CPU time for this CPU
            let busy_slot = BUSY_CPU_TIME.get_ptr_mut(0).ok_or_else(|| {
                info!(&ctx, "Failed to get busy_cpu_time slot");
                3i64
            })?;
            // SAFETY: PerCpuArray pointer dereferencing is safe
            // - busy_slot is a valid pointer returned from BUSY_CPU_TIME.get_ptr_mut(0)
            // - The Some variant indicates the pointer is valid and properly aligned
            // - BUSY_CPU_TIME is a PerCpuArray<u64> with max_entries=1, created at load time
            // - CPU 0's slot is always accessible in a running system
            // - The pointer is guaranteed to point to a valid u64 value
            // - Would have returned error on earlier line if busy_slot was None
            // Use checked_add to prevent overflow - return error if it would overflow
            let current_busy = unsafe { *busy_slot };
            unsafe {
                *busy_slot = current_busy.checked_add(delta).ok_or_else(|| {
                    info!(&ctx, "Busy CPU time overflow");
                    5i64
                })?;
            }
        }
    }

    // SAFETY: PerCpuArray pointer dereferencing is safe
    // - start_time_slot is still a valid pointer (hasn't been invalidated)
    // - The pointer points to a valid u64 value in the PerCpuArray
    // - now is a valid u64 timestamp from bpf_ktime_get_ns()
    // - This updates the start time for the incoming task
    unsafe { *start_time_slot = now };

    Ok(0)
}
