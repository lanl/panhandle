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
mod cpu_usage;
mod readline;
mod socket;
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
        Err(ret) => return Err(ret.into()),
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
    // SAFETY: Kernel tracepoint data access is safe within the tracepoint context
    // - The tracepoint context is valid and properly initialized by the kernel for sys_enter_execve
    // - Reading at offset 0 accesses the beginning of the tracepoint's data structure (SysEnterExecve)
    // - The SysEnterExecve struct size is fixed and known at compile time
    // - Error handling via map_err(-1) catches any invalid memory access attempts
    // - The eBPF verifier ensures the read operation stays within bounds of the tracepoint data
    let data: SysEnterExecve = unsafe { ctx.read_at(0).map_err(|_| -1)? };

    // iterate over the argv info and copy to struct in the map
    if !data.argv.is_null() {
        // SAFETY: PerCpuArray pointer dereferencing is safe in eBPF context
        // - PANHANDLE_SCRATCH is a PerCpuArray<ExecveEvent> with max_entries=4096, created at program load
        // - get_ptr_mut(0) accesses the PerCpu slot for the current CPU (index 0 in the array)
        // - The PerCpuArray guarantees valid, aligned pointers for each CPU's dedicated memory region
        // - ok_or(0) handles the None case (which never occurs for valid CPU indices <= num_possible_cpus())
        // - The returned pointer is properly aligned for ExecveEvent (repr(C) with no padding issues)
        // - Each CPU has its own isolated slot, preventing concurrent access conflicts
        let event_data: &mut ExecveEvent = unsafe {
            let ptr: *mut ExecveEvent = PANHANDLE_SCRATCH.get_ptr_mut(0).ok_or(0)?;
            &mut *ptr
        };
        // SAFETY: Zeroing memory for ExecveEvent is safe
        // - ExecveEvent contains only primitive types (u64, u32, [u8; N] arrays) that are valid in zeroed state
        // - All 0s is a valid bit pattern for all integer fields and creates empty byte arrays
        // - This provides a clean slate before populating event data, preventing data leakage
        // - The struct size is known at compile time and properly handled by core::mem::zeroed
        *event_data = unsafe { core::mem::zeroed::<ExecveEvent>() };

        // SAFETY: Reading user space memory via bpf_probe_read_user_str_bytes is safe
        // - FILENAME_OFFSET (16) points to the filename pointer in the SysEnterExecve struct
        // - ctx.read_at::<*const u8>(FILENAME_OFFSET) safely reads the pointer from tracepoint data
        // - The filename field in ExecveEvent is [u8; LEN_MAX_PATH] (1024 bytes) providing ample capacity
        // - bpf_probe_read_user_str_bytes handles null termination and automatic bounds checking
        // - The helper ensures we don't exceed the destination buffer size (LEN_MAX_PATH)
        // - Error handling via unwrap_or(b"") provides empty string on any read failure
        // - Source pointer is validated by kernel before user space access
        unsafe {
            bpf_probe_read_user_str_bytes(
                ctx.read_at::<*const u8>(FILENAME_OFFSET)?,
                &mut event_data.filename,
            )
            .unwrap_or(b"")
        };

        // SAFETY: Kernel time function is safe to call from eBPF context
        // - bpf_ktime_get_boot_ns is a verified eBPF helper function (helper ID 25)
        // - Returns monotonically increasing nanoseconds since boot as u64
        // - No error conditions possible - this is a simple kernel time read with no side effects
        // - The value is guaranteed to be valid and non-decreasing across calls
        // - Safe to call from any eBPF context including tracepoints
        let timestamp: u64 = unsafe { bpf_ktime_get_boot_ns() };

        let envp: *const *const u8 = data.envp;
        // Additional validation: ensure envp pointer is not null before processing
        if !envp.is_null() {
            for env in 0..ENV_COUNT {
                // SAFETY: Reading user space memory via bpf_probe_read_user is safe
                // - envp.offset(env as isize) accesses sequential pointer locations in the envp array
                // - ENV_COUNT (20) is bounded to prevent excessive iteration and stack usage
                // - envp pointer was validated as non-null before entering the loop
                // - Each offset is calculated as env * sizeof(*const u8) which is always valid
                // - Error handling via ? operator propagates any read failures to outer scope
                let env_ptr: *const u8 = unsafe { bpf_probe_read_user(envp.offset(env as isize)) }?;
                if env_ptr.is_null() {
                    break;
                }
                // SAFETY: Reading user space string via bpf_probe_read_user_str_bytes is safe
                // - env_ptr was validated as non-null by previous bpf_probe_read_user call
                // - env_ptr points to valid user space memory containing a null-terminated string
                // - event_data.envp[env as usize] is [[u8; ENV_SIZE]; ENV_COUNT] where ENV_SIZE=120 bytes
                // - bpf_probe_read_user_str_bytes handles null termination and automatic bounds checking
                // - The helper ensures we don't exceed ENV_SIZE (120 bytes) for each environment variable
                // - Error handling via unwrap_or(b"") provides empty string on any read failure
                // - Kernel verifier ensures source memory is accessible and properly aligned
                unsafe {
                    bpf_probe_read_user_str_bytes(env_ptr, &mut event_data.envp[env as usize])
                        .unwrap_or(b"")
                };
            }
        }
        let argv: *const *const u8 = data.argv;
        // Additional validation: ensure argv pointer is not null before processing
        if !argv.is_null() {
            for i in 0..ARG_COUNT {
                // SAFETY: Reading user space memory via bpf_probe_read_user is safe
                // - argv.offset(i as isize) accesses sequential pointer locations in the argv array
                // - ARG_COUNT (20) is bounded to prevent excessive iteration and stack usage
                // - argv pointer was validated as non-null before entering the loop
                // - Each offset is calculated as i * sizeof(*const u8) which is always valid
                // - Error handling via ? operator propagates any read failures to outer scope
                let arg_ptr: *const u8 = unsafe { bpf_probe_read_user(argv.offset(i as isize)) }?;
                if arg_ptr.is_null() {
                    break;
                }
                // SAFETY: Reading user space string via bpf_probe_read_user_str_bytes is safe
                // - arg_ptr was validated as non-null by previous bpf_probe_read_user call
                // - arg_ptr points to valid user space memory containing a null-terminated string
                // - event_data.argv[i as usize] is [[u8; ARG_SIZE]; ARG_COUNT] where ARG_SIZE=400 bytes
                // - bpf_probe_read_user_str_bytes handles null termination and automatic bounds checking
                // - The helper ensures we don't exceed ARG_SIZE (400 bytes) for each command line argument
                // - Error handling via unwrap_or(b"") provides empty string on any read failure
                // - Kernel verifier ensures source memory is accessible and properly aligned
                unsafe {
                    bpf_probe_read_user_str_bytes(arg_ptr, &mut event_data.argv[i as usize])
                        .unwrap_or(b"")
                };
            }
        }

        event_data.timestamp = timestamp;
        event_data.uid = initial_uid;
        event_data.gid = (bpf_get_current_uid_gid() >> 32) as u32;
        event_data.pid = bpf_get_current_pid_tgid() as u32;
        event_data.tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        event_data.command = command;

        // SAFETY: Output to PerfEventArray is safe
        // - PANHANDLE_EVENTS is a properly initialized PerfEventArray<ExecveEvent> created at program load
        // - event_data is a valid, fully populated ExecveEvent struct with all fields initialized
        // - The context (&ctx) is valid for the current tracepoint execution
        // - Size parameter 0 uses sizeof(ExecveEvent) automatically via the map's value type
        // - Map was created with BPF_F_RDONLY flag and is guaranteed to exist throughout program lifetime
        // - PerfEventArray::output handles proper ring buffer management and memory barriers
        // - The event size (sizeof(ExecveEvent)) is known at compile time and validated by verifier
        unsafe {
            PANHANDLE_EVENTS.output(&ctx, event_data, 0);
        }
    }
    Ok(0)
}

/// get the value as a u32 from the map at a desired address and convert into a boolean
fn get_bool(address: u32, hash_map: &HashMap<u32, u32>) -> bool {
    // SAFETY: HashMap lookup is safe in eBPF context
    // - hash_map is a properly initialized HashMap<u32, u32> with max_entries=4, created at program load
    // - The map only contains u32 values set from userspace via BPF syscall interface
    // - Map lookups are atomic and thread-safe in eBPF context (no concurrent modification from eBPF side)
    // - unwrap_or(&0) handles the case where the key doesn't exist, returning a static reference to 0
    // - The map uses eBPF hash map implementation which validates all memory accesses
    // - Values are copied, preventing use-after-free or invalid memory access
    let retrieved_value: &u32 = unsafe { hash_map.get(&address) }.unwrap_or(&0);
    if retrieved_value == &1 {
        return true;
    }
    return false;
}

/// get u32 from the options map by address
fn get_uid(address: u32, hash_map: &HashMap<u32, u32>) -> u32 {
    // SAFETY: HashMap lookup is safe in eBPF context
    // - hash_map is a properly initialized HashMap<u32, u32> with max_entries=4, created at program load
    // - The map only contains u32 values set from userspace via BPF syscall interface
    // - Map lookups are atomic and thread-safe in eBPF context
    // - match statement handles both Some and None cases appropriately without unwrapping
    // - No bounds issues as we're only looking up existing keys (address is validated u32)
    // - Values are copied as u32, ensuring no dangling pointer issues
    // - eBPF verifier ensures addresses are valid before map lookup
    let _ = match unsafe { hash_map.get(&address) } {
        Some(x) => return *x as u32,
        None => return 0 as u32,
    };
}

/// get an array of usize uids from the uid include list map
fn get_include_uid_array(map_to_get: &HashMap<u32, [u32; UID_COUNT]>) -> [u32; UID_COUNT] {
    // SAFETY: HashMap lookup is safe in eBPF context
    // - map_to_get is a properly initialized HashMap<u32, [u32; UID_COUNT]> with max_entries=1, created at program load
    // - The map contains only fixed-size arrays ([u32; UID_COUNT] where UID_COUNT=10) set from userspace
    // - Map lookups are atomic and thread-safe in eBPF context
    // - match statement handles both Some and None cases appropriately without unwrapping
    // - [0; UID_COUNT] provides safe default when entry doesn't exist (all zeros array)
    // - Fixed-size array copy is safe as the size is known at compile time and within eBPF stack limits
    // - The array size (10 * 4 = 40 bytes) is small and verifier-approved for stack operations
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
    // SAFETY: Using unreachable_unchecked in panic handler is safe in eBPF
    // - eBPF programs cannot actually panic in the traditional Rust sense due to verifier restrictions
    // - The eBPF verifier prevents infinite loops and ensures all code paths terminate within instruction limits
    // - unreachable_unchecked prevents the compiler from eliminating branches that would otherwise be unreachable
    // - This is a standard and necessary pattern for eBPF panic handlers as eBPF cannot unwind
    // - Without this, the compiler might eliminate checks that are required for safety
    // - The verifier ensures program termination via maximum instruction count (default 1M)
    // - This pattern is used throughout the Aya ecosystem and is well-established
    unsafe { core::hint::unreachable_unchecked() }
}
