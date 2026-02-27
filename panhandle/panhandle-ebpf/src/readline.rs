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
/// this is the ebpf program to access the libreadline entries via
/// the readline or readline teardown method.

#[map(name = "readline_events")]
static mut READLINE_EVENTS: PerfEventArray<Readline> = PerfEventArray::new(0);
#[map(name = "readline_scratch")]
pub static READLINE_SCRATCH: PerCpuArray<Readline> = PerCpuArray::with_max_entries(4096, 0);
#[map(name = "readline_uid_options")]
static READLINE_UID_OPTIONS: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(4, 0);
#[map(name = "readline_uid_include_list")]
static READLINE_UID_INCLUDE_LIST: HashMap<u32, [u32; UID_COUNT]> =
    HashMap::<u32, [u32; UID_COUNT]>::with_max_entries(1, 0);

#[uretprobe]
pub fn readline(ctx: RetProbeContext) -> u32 {
    match try_readline(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_readline(ctx: RetProbeContext) -> Result<u32, i64> {
    // get the pointer to this event
    let ret_ptr: *const u8 = ctx.ret().unwrap();

    let initial_uid: u32 = bpf_get_current_uid_gid() as u32;
    // skip event if the uid is not in the range of UIDs
    if exclude_uid(initial_uid, &READLINE_UID_OPTIONS) {
        return Ok(0);
    }

    // skip if not in the include uids list
    // the uid_options map has an entry for if the uid_include_list is defined / desired in userland to reduce overhead
    if get_bool(3, &READLINE_UID_OPTIONS) {
        if !check_uid_in_uidarray(&initial_uid, &READLINE_UID_INCLUDE_LIST) {
            return Ok(0);
        }
    }

    // SAFETY: we are getting and copying a reference to our self-defined struct,
    // the map is created on program load
    let event: &mut Readline = unsafe {
        let ptr: *mut Readline = READLINE_SCRATCH.get_ptr_mut(0).ok_or(0)?;
        &mut *ptr
    };
    // SAFETY: Readline only holds ints and byte arrays, and all 0s is a valid byte-pattern
    // for each of those.
    *event = unsafe { core::mem::zeroed::<Readline>() };

    // add in the data from the ebpf methods related to this event
    // SAFETY: this is a core BPF method implemented in Aya, the error condition is handled by an empty bytestring
    unsafe { bpf_probe_read_user_str_bytes(ret_ptr, &mut event.entry).unwrap_or(b"") };

    // get the command
    event.command = ctx.command().unwrap_or_default();

    // SAFETY: this is a core BPF method implemented in Aya
    event.timestamp = unsafe { bpf_ktime_get_boot_ns() };
    event.uid = initial_uid;
    event.gid = (bpf_get_current_uid_gid() >> 32) as u32;
    event.pid = bpf_get_current_pid_tgid() as u32;
    event.tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // output the event to the userspace program
    // SAFETY: this map is created with a custom struct, the struct is zeroed before population
    // the map is created on program load
    unsafe {
        READLINE_EVENTS.output(&ctx, event, 0);
    }

    Ok(0)
}
