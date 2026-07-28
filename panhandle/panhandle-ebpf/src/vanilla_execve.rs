#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(static_mut_refs)]
#![allow(unused_imports)]
/// this is the ebpf program to access zsh commandline entries via the zlentry method
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_boot_ns, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{PerCpuArray, PerfEventArray, RingBuf},
    programs::TracePointContext,
};
use panhandle_common::*;

#[map]
pub static EXECVE_SCRATCH: PerCpuArray<ExecveEvent> = PerCpuArray::with_max_entries(256, 0);
#[map(name = "vanilla_execve_events")]
static mut EXECVE_EVENTS: PerfEventArray<ExecveEvent> = PerfEventArray::new(0);

#[tracepoint]
pub fn monitor_execve(ctx: TracePointContext) -> u32 {
    match try_monitor_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_monitor_execve(ctx: TracePointContext) -> Result<u32, i64> {
    let uid: u32 = bpf_get_current_uid_gid() as u32;
    if (uid >= MINUID) && (uid <= MAXUID) {
        // SAFETY: PerCpuArray pointer dereferencing is safe in eBPF context
        // - EXECVE_SCRATCH is a PerCpuArray<ExecveEvent> with max_entries=4096, created at program load
        // - get_ptr_mut(0) returns a valid pointer for CPU 0's slot
        // - The pointer is only used when Some is returned, error handled via ok_or(0)
        // - The struct is properly aligned for ExecveEvent type
        let event: &mut ExecveEvent = unsafe {
            let ptr: *mut ExecveEvent = EXECVE_SCRATCH.get_ptr_mut(0).ok_or(0)?;
            &mut *ptr
        };
        event.command = bpf_get_current_comm()?;
        event.uid = uid;
        event.pid = bpf_get_current_pid_tgid() as u32;
        event.tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        event.gid = (bpf_get_current_uid_gid() >> 32) as u32;

        // SAFETY: bpf_ktime_get_boot_ns is a verified eBPF helper function
        // - Returns monotonically increasing nanoseconds since boot
        // - No error conditions as it's a simple time read
        // - Provided by Aya library which wraps the kernel helper
        event.timestamp = unsafe { bpf_ktime_get_boot_ns() };
        //info!(&ctx, "filename: {}, command: {}, uid: {}, pid: {}, gid: {}, tgid: {}", event.filename, event.command, event.uid, event.pid, event.gid, event.tgid);

        // SAFETY: Output to PerfEventArray is safe
        // - EXECVE_EVENTS is a properly initialized PerfEventArray<ExecveEvent>
        // - event is a valid, populated ExecveEvent struct
        // - The context is valid for the current tracepoint
        // - Size parameter 0 uses the struct size automatically
        // - Map was created at program load and is guaranteed to exist
        unsafe {
            EXECVE_EVENTS.output(&ctx, event, 0);
        }
    }
    Ok(0)
}
