#![allow(static_mut_refs)]
use core::u8;

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_boot_ns,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, uretprobe},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::RetProbeContext,
};
use panhandle_common::Readline;

use crate::*;
/// this is a copy of the readline entry and should be kept up to date with it, the goal is to allow a readline+zlentry access

#[map(name = "zlentry_events")]
static mut ZLENTRY_EVENTS: PerfEventArray<Readline> = PerfEventArray::new(0);
#[map(name = "zlentry_scratch")]
pub static ZLENTRY_SCRATCH: PerCpuArray<Readline> = PerCpuArray::with_max_entries(256, 0);
#[map(name = "zlentry_uid_options")]
static ZLENTRY_UID_OPTIONS: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(4, 0);
#[map(name = "zlentry_uid_include_list")]
static ZLENTRY_UID_INCLUDE_LIST: HashMap<u32, [u32; UID_COUNT]> =
    HashMap::<u32, [u32; UID_COUNT]>::with_max_entries(1, 0);

#[uretprobe]
pub fn zlentry(ctx: RetProbeContext) -> u32 {
    match try_zlentry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_zlentry(ctx: RetProbeContext) -> Result<u32, i64> {
    // get the pointer to this event
    // SAFETY: ctx.ret() returns the return value from the probed function
    // - For zlentry, this is a pointer to the input string
    // - In eBPF uretprobe context, this should be a valid pointer or null
    let ret_ptr: *const u8 = ctx.ret();
    // Null pointer check: ret_ptr must not be null for valid zlentry return
    if ret_ptr.is_null() {
        return Ok(0);
    }
    let initial_uid: u32 = bpf_get_current_uid_gid() as u32;

    // skip event if the uid is not in the range of UIDs
    if exclude_uid(initial_uid, &ZLENTRY_UID_OPTIONS) {
        return Ok(0);
    }

    // skip if not in the include uids list
    // the uid_options map has an entry for if the uid_include_list is defined / desired in userland to reduce overhead
    if get_bool(3, &ZLENTRY_UID_OPTIONS) {
        if !check_uid_in_uidarray(&initial_uid, &ZLENTRY_UID_INCLUDE_LIST) {
            return Ok(0);
        }
    }

    // SAFETY: PerCpuArray pointer dereferencing is safe in eBPF context
    // - ZLENTRY_SCRATCH is a PerCpuArray<Readline> with max_entries=4096, created at program load
    // - get_ptr_mut(0) returns a valid pointer for the current CPU's slot (index 0)
    // - The pointer is only used when Some is returned, error handled via ok_or(0)
    // - The struct is properly aligned for Readline type
    // - PerCpuArray guarantees valid, non-null pointers for allocated slots
    // - eBPF verifier ensures the pointer remains valid for the duration of this context
    let event: &mut Readline = unsafe {
        let ptr: *mut Readline = ZLENTRY_SCRATCH.get_ptr_mut(0).ok_or(0)?;
        // Null pointer check for defense in depth (verifier should catch this)
        if ptr.is_null() {
            return Err(0);
        }
        &mut *ptr
    };

    // SAFETY: Zeroing memory for Readline is safe
    // - Readline contains only primitive types (ints, byte arrays) that are valid in zeroed state
    // - All 0s is a valid bit pattern for all fields in Readline
    // - This provides a clean slate before populating event data
    *event = unsafe { core::mem::zeroed::<Readline>() };

    // SAFETY: Reading user space string via bpf_probe_read_user_str_bytes is safe
    // - ret_ptr points to valid user space memory (return value from zlentry function)
    // - ret_ptr has been validated as non-null above
    // - event.entry has fixed capacity (256 bytes) for command line input strings
    // - Error handling via unwrap_or provides empty string on failure
    // - bpf_probe_read_user_str_bytes handles null termination and bounds checking
    // - Buffer overflow protection: helper respects the capacity of event.entry
    // - Source validation: ret_ptr comes from verified uretprobe context
    unsafe { bpf_probe_read_user_str_bytes(ret_ptr, &mut event.entry).unwrap_or(b"") };

    // get the command
    // SAFETY: ctx.command() is safe to call in eBPF probe context
    // - command() returns the path of the probed function (zsh zlentry)
    // - unwrap_or_default() handles None case by providing empty array
    // - In uretprobe context, command() should always return Some for valid probes
    // - The Aya library ensures the command string is properly encoded
    // - Empty default is acceptable for error cases (non-critical field)
    event.command = ctx.command().unwrap_or_default();

    // SAFETY: bpf_ktime_get_boot_ns is a verified eBPF helper function
    // - Returns monotonically increasing nanoseconds since boot
    // - No error conditions as it's a simple time read
    // - Provided by Aya library which wraps the kernel helper
    event.timestamp = unsafe { bpf_ktime_get_boot_ns() };
    event.uid = initial_uid;
    event.gid = (bpf_get_current_uid_gid() >> 32) as u32;
    event.pid = bpf_get_current_pid_tgid() as u32;
    event.tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // output the event to the userspace program
    // SAFETY: Output to PerfEventArray is safe
    // - ZLENTRY_EVENTS is a properly initialized PerfEventArray<Readline>
    // - event is a valid, populated Readline struct
    // - The context is valid for the current uretprobe
    // - Size parameter 0 uses the struct size automatically
    // - Map was created at program load and is guaranteed to exist
    unsafe {
        ZLENTRY_EVENTS.output(&ctx, event, 0);
    }

    Ok(0)
}
