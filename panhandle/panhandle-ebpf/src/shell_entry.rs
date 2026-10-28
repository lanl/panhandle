#![allow(static_mut_refs)]

use crate::*;
use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_boot_ns,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, uretprobe},
    maps::RingBuf,
    programs::RetProbeContext,
};
use aya_log_ebpf::{debug, warn};
use panhandle_common::Readline;

/// Shared implementation for capturing shell command-line entries via libreadline's
/// (bash) or zle's (zsh) teardown hooks. Both shells need their own top-level
/// `#[uretprobe]` function (each is attached to a different target binary/symbol), but
/// they funnel through the same event-population logic below.

// 256 KiB: Readline entries are ~440 bytes each
#[map(name = "readline_events")]
static READLINE_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 18, 0);

#[map(name = "zlentry_events")]
static ZLENTRY_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 18, 0);

/// GlobalData for shell configuration - shared between readline and zlentry
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ShellConfig {
    pub shells: u32,
    pub exclude_min_uid: u32,
    pub exclude_max_uid: u32,
    pub include_enabled: u32,
    pub include_uids: [u32; UID_COUNT],
}

#[unsafe(link_section = ".bss")]
static mut SHELL_CONFIG: ShellConfig = ShellConfig {
    shells: 0,
    exclude_min_uid: MINUID,
    exclude_max_uid: MAXUID,
    include_enabled: 0,
    include_uids: [0; UID_COUNT],
};

#[uretprobe]
pub fn readline(ctx: RetProbeContext) -> u32 {
    match try_shell_entry(&ctx, "readline", &READLINE_EVENTS) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[uretprobe]
pub fn zlentry(ctx: RetProbeContext) -> u32 {
    match try_shell_entry(&ctx, "zlentry", &ZLENTRY_EVENTS) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn get_shell_config() -> &'static ShellConfig {
    unsafe { &SHELL_CONFIG }
}

#[allow(dead_code)]
fn get_shells() -> bool {
    let config = get_shell_config();
    config.shells == 1
}

fn get_exclude_min_uid() -> u32 {
    let config = get_shell_config();
    config.exclude_min_uid
}

fn get_exclude_max_uid() -> u32 {
    let config = get_shell_config();
    config.exclude_max_uid
}

fn get_include_enabled() -> bool {
    let config = get_shell_config();
    config.include_enabled == 1
}

fn get_include_uids() -> [u32; UID_COUNT] {
    let config = get_shell_config();
    config.include_uids
}

fn exclude_uid(uid: u32) -> bool {
    let min = get_exclude_min_uid();
    let max = get_exclude_max_uid();
    if (uid >= min) && (uid <= max) {
        return true;
    }
    return false;
}

fn check_uid_in_uidarray(uid: &u32) -> bool {
    let only_uids_list = get_include_uids();

    // compare initial uid to array, stop at first match
    for value in only_uids_list.iter() {
        if value == uid {
            return true;
        }
    }
    return false;
}

#[inline(always)]
fn try_shell_entry(ctx: &RetProbeContext, name: &str, events: &RingBuf) -> Result<u32, i64> {
    // get the pointer to this event
    let ret_ptr: *const u8 = ctx.ret();
    let initial_uid: u32 = bpf_get_current_uid_gid() as u32;

    // skip event if the uid is not in the range of UIDs
    if exclude_uid(initial_uid) {
        debug!(
            ctx,
            "{}: skipping, uid {} excluded by range filter", name, initial_uid
        );
        return Ok(0);
    }

    // skip if not in the include uids list
    if get_include_enabled() && !check_uid_in_uidarray(&initial_uid) {
        debug!(
            ctx,
            "{}: skipping, uid {} not in include list", name, initial_uid
        );
        return Ok(0);
    }

    // SAFETY: reserve space directly in the ring buffer and populate it in place; this avoids
    // the extra copy through a scratch map that a perf array output required
    let mut entry = match events.reserve::<Readline>(0) {
        Some(entry) => entry,
        None => {
            warn!(
                ctx,
                "{}: ring buffer full, dropping event for uid {}", name, initial_uid
            );
            return Ok(0);
        }
    };
    let event: &mut Readline = unsafe {
        let ptr: *mut Readline = entry.as_mut_ptr();
        // SAFETY: Readline only holds ints and byte arrays, and all 0s is a valid byte-pattern
        // for each of those.
        *ptr = core::mem::zeroed();
        &mut *ptr
    };

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
    entry.submit(0);

    Ok(0)
}
