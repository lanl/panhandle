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

// hash map that stores total accumulated CPU time per process ID. 1024 is max amount of processes
#[map(name = "per_cpu_time")]
static PID_CPU_TIME: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

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
    // SAFETY: the kernel guarantees that the context points to a valid trace_event_raw_sched_switch struct for the sched_switch tracepoint
    let tp: *const trace_event_raw_sched_switch = ctx.as_ptr().cast();
    let prev_pid = unsafe { (*tp).prev_pid } as u32;

    // get current time
    // SAFETY: this is a core BPF function implemented in aya
    let now = unsafe { bpf_ktime_get_ns() };

    // handle the outgoing task
    let start_time_slot = START_TIMES.get_ptr_mut(0).ok_or_else(|| {
        info!(&ctx, "Failed to get start_time_slot");
        1i64
    })?;

    // SAFETY: start_time_slot is valid as we just got it from the map
    let prev_start = unsafe { *start_time_slot };

    // if task was running, account its runtime
    if prev_start != 0 {
        let delta = now - prev_start;

        if prev_pid != 0 {
            // update the per PID total
            match PID_CPU_TIME.get_ptr_mut(&prev_pid) {
                Some(entry) => {
                    // SAFETY: Activating Some block here means the entry is populated
                    unsafe { *entry += delta };
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
            // SAFETY: Would have gotten panic on earlier line if busy_slot was null
            unsafe { *busy_slot += delta };
        }
    }

    // now the start time for the incoming task is now
    unsafe { *start_time_slot = now };

    Ok(0)
}
