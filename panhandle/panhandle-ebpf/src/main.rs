#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(static_mut_refs)]
use core::u8;

use aya_ebpf::{
    bindings::BPF_F_RDONLY,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_boot_ns, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::TracePointContext,
};

use panhandle_common::*;
mod fmsh;
mod readline;
mod vanilla_execve;
mod zlentry;

#[map(name = "panhandle_execve_events")]
static mut PANHANDLE_EVENTS: PerfEventArray<ExecveEvent> = PerfEventArray::new(0);
#[map(name = "panhandle_scratch")]
pub static PANHANDLE_SCRATCH: PerCpuArray<ExecveEvent> =
    PerCpuArray::with_max_entries(4096, BPF_F_RDONLY);
#[map(name = "uid_options")]
static UID_OPTIONS: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(4, 0);
#[map(name = "uid_include_list")]
static UID_INCLUDE_LIST: HashMap<u32, [u32; UID_COUNT]> =
    HashMap::<u32, [u32; UID_COUNT]>::with_max_entries(1, 0);

#[tracepoint]
pub fn panhandle(ctx: TracePointContext) -> u32 {
    match try_panhandle(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_panhandle(ctx: TracePointContext) -> Result<u32, i64> {
    let initial_uid = bpf_get_current_uid_gid() as u32;

    // skip event if the uid is not in the range of UIDs
    if exclude_uid(initial_uid, &UID_OPTIONS) {
        return Ok(0);
    }

    // Get the comm (process name)
    let command: [u8; 16] = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(ret) => return Err(ret),
    };

    // filter out commands if shells
    let shells: bool = get_bool(0, &UID_OPTIONS);
    if shells {
        // let's make sure the shell matches the shells we are looking for
        let shell_bool: bool = check_shells(command);
        if !shell_bool {
            // this is *probably* not an shell
            return Ok(0);
        }
    }

    // skip if not in the include uids list
    // the uid_options map has an entry for if the uid_include_list is defined / desired in userland to reduce overhead
    if get_bool(3, &UID_OPTIONS) {
        if !check_uid_in_uidarray(&initial_uid, &UID_INCLUDE_LIST) {
            return Ok(0);
        }
    }

    // Read the tracepoint data into our SysEnterExecve struct.
    // SAFETY: this is defined per the kernel docs and may change by version but seems to be pretty stable
    // kernel-specific docs (RHEL path) /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
    let data: SysEnterExecve = unsafe { ctx.read_at(0).map_err(|_| -1)? };

    // iterate over the argv info and copy to struct in the map
    if !data.argv.is_null() {
        // SAFETY: we are getting and copying a reference to our self-defined struct,
        // the map is created on program load
        let event_data: &mut ExecveEvent = unsafe {
            let ptr: *mut ExecveEvent = PANHANDLE_SCRATCH.get_ptr_mut(0).ok_or(0)?;
            &mut *ptr
        };
        // SAFETY: ExecveEvent only holds ints and byte arrays, and all 0s is a valid byte-pattern
        // for each of those.
        *event_data = unsafe { core::mem::zeroed::<ExecveEvent>() };
        // SAFETY: this is a core BPF method implemented in Aya
        unsafe {
            bpf_probe_read_user_str_bytes(
                ctx.read_at::<*const u8>(FILENAME_OFFSET)?,
                &mut event_data.filename,
            )
            .unwrap_or(b"");
        };
        // SAFETY: this is a core BPF method implemented in Aya
        let timestamp: u64 = unsafe { bpf_ktime_get_boot_ns() };

        let envp: *const *const u8 = data.envp;
        for env in 0..ENV_COUNT {
            // SAFETY: this is a core BPF method implemented in Aya, the null condition is handled
            let env_ptr: *const u8 = unsafe { bpf_probe_read_user(envp.offset(env as isize)) }?;
            if env_ptr.is_null() {
                break;
            }
            // SAFETY: this is a core BPF method implemented in Aya, the error condition is handled by an empty bytestring
            unsafe {
                bpf_probe_read_user_str_bytes(env_ptr, &mut event_data.envp[env as usize])
                    .unwrap_or(b"")
            };
        }
        let argv: *const *const u8 = data.argv;
        for i in 0..ARG_COUNT {
            // SAFETY: this is a core BPF method implemented in Aya, the null condition is handled
            let arg_ptr: *const u8 = unsafe { bpf_probe_read_user(argv.offset(i as isize)) }?;
            if arg_ptr.is_null() {
                break;
            }
            // SAFETY: this is a core BPF method implemented in Aya, the error condition is handled by an empty bytestring
            unsafe {
                bpf_probe_read_user_str_bytes(arg_ptr, &mut event_data.argv[i as usize])
                    .unwrap_or(b"")
            };
        }

        event_data.timestamp = timestamp;
        event_data.uid = initial_uid;
        event_data.gid = (bpf_get_current_uid_gid() >> 32) as u32;
        event_data.pid = bpf_get_current_pid_tgid() as u32;
        event_data.tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        event_data.command = command;

        // SAFETY: this map is created with a custom struct, the struct is zeroed before population
        // the map is created on program load
        unsafe {
            PANHANDLE_EVENTS.output(&ctx, event_data, 0);
        }
    }
    Ok(0)
}

/// get the value as a u32 from the map at a desired address and convert into a boolean
fn get_bool(address: u32, hash_map: &HashMap<u32, u32>) -> bool {
    // SAFETY: this map holds only u32s filled from the user side, condition if they don't exist is handled.
    let retrieved_value: &u32 = unsafe { hash_map.get(&address) }.unwrap_or(&0);
    if retrieved_value == &1 {
        return true;
    }
    return false;
}

/// get u32 from the options map by address
fn get_uid(address: u32, hash_map: &HashMap<u32, u32>) -> u32 {
    // SAFETY: this map holds only u32s filled from the user side, condition if they don't exist is handled.
    let _ = match unsafe { hash_map.get(&address) } {
        Some(x) => return *x as u32,
        None => return 0 as u32,
    };
}

/// get an array of usize uids from the uid include list map
fn get_include_uid_array(map_to_get: &HashMap<u32, [u32; UID_COUNT]>) -> [u32; UID_COUNT] {
    // SAFETY: this map holds only an array of UID_COUNT x u32s filled from the user side, condition if they don't exist is handled.
    let _: [u32; UID_COUNT] = match unsafe { map_to_get.get(&0) } {
        Some(x) => return *x,
        None => return [0; UID_COUNT],
    };
}

/// return a bool to deftermine if the process should be excluded by uid
fn exclude_uid(uid: u32, hash_map: &HashMap<u32, u32>) -> bool {
    let min = get_uid(1, hash_map);
    let max = get_uid(2, hash_map);
    if (uid >= min) && (uid <= max) {
        return true;
    }
    return false;
}

/// check the command against the list of valid shells we want to monitor, requires byte comparison to avoid string comparisons in ebpf-land
fn check_shells(command: [u8; 16]) -> bool {
    let mut check_bool = false;
    // let's make sure the shell matches the shells we are looking for
    if command[0..2] == *b"sh" {
        check_bool = true
    } else if command[0..4] == *b"bash" {
        check_bool = true
    } else if command[0..3] == *b"zsh" {
        check_bool = true
    } else if command[0..4] == *b"tcsh" {
        check_bool = true
    } else if command[0..3] == *b"csh" {
        check_bool = true
    }
    check_bool
}

/// check if a given u32 uid matches the list of u32 uids to look for
fn check_uid_in_uidarray(uid: &u32, hash_map: &HashMap<u32, [u32; UID_COUNT]>) -> bool {
    let only_uids_list = get_include_uid_array(hash_map);

    // compare initial uid to array, stop at first match
    for value in only_uids_list.iter() {
        if value == uid {
            return true;
        }
    }
    return false;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: call to prevent compiler from eliminating branches to maintain loop
    unsafe { core::hint::unreachable_unchecked() }
}
