#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(static_mut_refs)]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_boot_ns, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::{debug, warn};
use panhandle_common::*;
mod blocker;
mod network_bound;
mod shell_entry;
mod socket;
mod vmlinux;

// 1 MiB: ExecveEvent is ~11KB, so this comfortably buffers bursts of execve activity
#[map(name = "panhandle_execve_events")]
static PANHANDLE_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);
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
        debug!(
            &ctx,
            "execve: skipping, uid {} excluded by range filter", initial_uid
        );
        return Ok(0);
    }

    // Get the comm (process name)
    let command: [u8; 16] = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(ret) => return Err(ret as i64),
    };

    // filter out commands if shells
    let shells: bool = get_bool(UID_OPT_SHELLS, &UID_OPTIONS);
    if shells {
        // let's make sure the shell matches the shells we are looking for
        let shell_bool: bool = check_shells(command);
        if !shell_bool {
            // this is *probably* not an shell
            debug!(&ctx, "execve: skipping, comm does not match shell filter");
            return Ok(0);
        }
    }

    // skip if not in the include uids list
    // the uid_options map has an entry for if the uid_include_list is defined / desired in userland to reduce overhead
    if get_bool(UID_OPT_INCLUDE_ENABLED, &UID_OPTIONS)
        && !check_uid_in_uidarray(&initial_uid, &UID_INCLUDE_LIST)
    {
        debug!(
            &ctx,
            "execve: skipping, uid {} not in include list", initial_uid
        );
        return Ok(0);
    }

    // Read the tracepoint data into our SysEnterExecve struct.
    // SAFETY: this is defined per the kernel docs and may change by version but seems to be pretty stable
    // kernel-specific docs (RHEL path) /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
    let data: SysEnterExecve = unsafe { ctx.read_at(0).map_err(|_| -1)? };
    let filename_ptr: *const u8 = data.command;
    let argv_ptr: *const *const u8 = data.argv;
    let envp_ptr: *const *const u8 = data.envp;

    // iterate over the argv info and copy to struct in the map
    if !argv_ptr.is_null() {
        // SAFETY: reserve space directly in the ring buffer and populate it in place; this
        // avoids the extra copy through a scratch map that a perf array output required
        let mut entry = match PANHANDLE_EVENTS.reserve::<ExecveEvent>(0) {
            Some(entry) => entry,
            None => {
                warn!(
                    &ctx,
                    "execve: ring buffer full, dropping event for uid {}", initial_uid
                );
                return Ok(0);
            }
        };
        let event_data: &mut ExecveEvent = unsafe {
            let ptr: *mut ExecveEvent = entry.as_mut_ptr();
            // zero out this memory in case of artifacts
            *ptr = core::mem::zeroed();
            &mut *ptr
        };

        // SAFETY: this is a core BPF method implemented in Aya
        unsafe {
            let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut event_data.filename);
        };
        // SAFETY: this is a core BPF method implemented in Aya
        let timestamp: u64 = unsafe { bpf_ktime_get_boot_ns() };

        // Read envp with explicit bound-reassurance for the verifier
        for env in 0..ENV_COUNT {
            let env_ptr = match unsafe { bpf_probe_read_user(envp_ptr.add(env)) } {
                Ok(ptr) => ptr,
                Err(_) => break,
            };
            if env_ptr.is_null() {
                break;
            }

            // Reassure the verifier that env is safely within bounds
            if env < ENV_COUNT {
                unsafe {
                    bpf_probe_read_user_str_bytes(env_ptr, &mut event_data.envp[env])
                        .unwrap_or(b"");
                };
            }
        }

        // Read argv with explicit bound-reassurance for the verifier
        for i in 0..ARG_COUNT {
            let arg_ptr = match unsafe { bpf_probe_read_user(argv_ptr.add(i)) } {
                Ok(ptr) => ptr,
                Err(_) => break,
            };
            if arg_ptr.is_null() {
                break;
            }

            // Reassure the verifier that i is safely within bounds
            if i < ARG_COUNT {
                unsafe {
                    bpf_probe_read_user_str_bytes(arg_ptr, &mut event_data.argv[i]).unwrap_or(b"");
                };
            }
        }

        event_data.timestamp = timestamp;
        event_data.uid = initial_uid;
        event_data.gid = (bpf_get_current_uid_gid() >> 32) as u32;
        event_data.pid = bpf_get_current_pid_tgid() as u32;
        event_data.tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        event_data.command = command;

        entry.submit(0);
    }
    Ok(0)
}

/// get the value as a u32 from the map at a desired address and convert into a boolean
pub fn get_bool(address: u32, hash_map: &HashMap<u32, u32>) -> bool {
    // SAFETY: this map holds only u32s filled from the user side, condition if they don't exist is handled.
    let retrieved_value: &u32 = unsafe { hash_map.get(&address) }.unwrap_or(&0);
    retrieved_value == &1
}

/// get u32 from the options map by address
pub fn get_uid(address: u32, hash_map: &HashMap<u32, u32>) -> u32 {
    // SAFETY: this map holds only u32s filled from the user side, condition if they don't exist is handled.
    match unsafe { hash_map.get(&address) } {
        Some(x) => *x,
        None => 0,
    }
}

/// get an array of usize uids from the uid include list map
pub fn get_include_uid_array(map_to_get: &HashMap<u32, [u32; UID_COUNT]>) -> [u32; UID_COUNT] {
    // SAFETY: this map holds only an array of UID_COUNT x u32s filled from the user side, condition if they don't exist is handled.
    match unsafe { map_to_get.get(&0) } {
        Some(x) => *x,
        None => [0; UID_COUNT],
    }
}

/// return a bool to determine if the process should be excluded by uid
pub fn exclude_uid(uid: u32, hash_map: &HashMap<u32, u32>) -> bool {
    let min = get_uid(UID_OPT_EXCLUDE_MIN, hash_map);
    let max = get_uid(UID_OPT_EXCLUDE_MAX, hash_map);
    if (uid >= min) && (uid <= max) {
        return true;
    }
    false
}

/// check the command against the list of valid shells we want to monitor, requires byte comparison to avoid string comparisons in ebpf-land
fn check_shells(command: [u8; 16]) -> bool {
    // let's make sure the shell matches the shells we are looking for
    is_exact_comm(&command, b"sh")
        || is_exact_comm(&command, b"bash")
        || is_exact_comm(&command, b"zsh")
        || is_exact_comm(&command, b"tcsh")
        || is_exact_comm(&command, b"csh")
}

/// Returns true if `command` (a NUL-padded comm buffer) is exactly `name` -
/// i.e. `name` is a prefix of it AND is immediately followed by the NUL
/// terminator, so e.g. "sh" matches comm "sh" but not "shutdown" or "shred".
fn is_exact_comm(command: &[u8; 16], name: &[u8]) -> bool {
    let len = name.len();
    command[..len] == *name && command[len] == 0
}

/// check if a given u32 uid matches the list of u32 uids to look for
pub fn check_uid_in_uidarray(uid: &u32, hash_map: &HashMap<u32, [u32; UID_COUNT]>) -> bool {
    let only_uids_list = get_include_uid_array(hash_map);

    // compare initial uid to array, stop at first match
    for value in only_uids_list.iter() {
        if value == uid {
            return true;
        }
    }
    false
}

// TestRun infrastructure for eBPF unit tests

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: call to prevent compiler from eliminating branches to maintain loop
    unsafe { core::hint::unreachable_unchecked() }
}
// These tests run in userspace to verify eBPF program logic
// Note: TestRun-based tests require the eBPF binary to be built first (via aya-build),
// so they are conditionally compiled only when the binary exists.
#[cfg(test)]
mod tests {
    use super::*;
    use panhandle_common::UID_COUNT;

    /// Test shell command filtering logic
    #[test]
    fn test_check_shells() {
        // Test exact matches
        let mut sh_comm = [0u8; 16];
        sh_comm[..2].copy_from_slice(b"sh");
        assert!(check_shells(sh_comm));

        let mut bash_comm = [0u8; 16];
        bash_comm[..4].copy_from_slice(b"bash");
        assert!(check_shells(bash_comm));

        let mut zsh_comm = [0u8; 16];
        zsh_comm[..3].copy_from_slice(b"zsh");
        assert!(check_shells(zsh_comm));

        // Test non-matches (prefix but not exact)
        let mut shutdown_comm = [0u8; 16];
        shutdown_comm[..8].copy_from_slice(b"shutdown");
        assert!(!check_shells(shutdown_comm));

        let mut bashrc_comm = [0u8; 16];
        bashrc_comm[..6].copy_from_slice(b"bashrc");
        assert!(!check_shells(bashrc_comm));
    }

    /// Test UID include list logic
    #[test]
    fn test_check_uid_in_uidarray() {
        // uid_options/uid_include_list are real eBPF maps, which can't be constructed
        // host-side outside of a loaded eBPF program, so we can't exercise
        // check_uid_in_uidarray/exclude_uid directly here. This at least checks the
        // shared constant they're built against stays in sync.
        assert_eq!(UID_COUNT, 10);
    }
}
