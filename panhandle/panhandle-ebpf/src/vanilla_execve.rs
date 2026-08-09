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
    maps::RingBuf,
    programs::TracePointContext,
};
use panhandle_common::*;

// 1 MiB: ExecveEvent is ~11KB, so this comfortably buffers bursts of execve activity
#[map(name = "vanilla_execve_events")]
static EXECVE_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[tracepoint]
pub fn monitor_execve(ctx: TracePointContext) -> u32 {
    match try_monitor_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_monitor_execve(_ctx: TracePointContext) -> Result<u32, i64> {
    let uid: u32 = bpf_get_current_uid_gid() as u32;
    if (uid >= MINUID) && (uid <= MAXUID) {
        // SAFETY: reserve space directly in the ring buffer and populate it in place; this
        // avoids the extra copy through a scratch map that a perf array output required.
        // Note: as in the prior scratch-buffer version, only the fields below are populated -
        // argv/envp/filename are left as whatever bytes the reservation happened to contain.
        let mut entry = EXECVE_EVENTS.reserve::<ExecveEvent>(0).ok_or(0)?;
        let event: &mut ExecveEvent = unsafe {
            let ptr: *mut ExecveEvent = entry.as_mut_ptr();
            &mut *ptr
        };
        event.command = bpf_get_current_comm()?;
        event.uid = uid;
        event.pid = bpf_get_current_pid_tgid() as u32;
        event.tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        event.gid = (bpf_get_current_uid_gid() >> 32) as u32;
        event.timestamp = unsafe { bpf_ktime_get_boot_ns() };
        //info!(&ctx, "filename: {}, command: {}, uid: {}, pid: {}, gid: {}, tgid: {}", event.filename, event.command, event.uid, event.pid, event.gid, event.tgid);

        entry.submit(0);
    }
    Ok(0)
}
