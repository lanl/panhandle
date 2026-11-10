#![allow(unexpected_cfgs)]
use aya_ebpf::{
    cty::c_long,
    helpers::{bpf_d_path, bpf_get_current_comm},
    macros::{lsm, lsm_cgroup, map},
    maps::{HashMap, PerCpuArray},
    programs::LsmContext,
};
use panhandle_common::{ALLOW_LIST, DENY_LIST, LIST_MODE};

const PATH_SIZE: usize = 256;

/// Byte offset of `f_path` within `struct file` on the running kernel, written by
/// userspace at load time from kernel BTF (see panhandle's btf_offsets.rs). Rust eBPF
/// code has no CO-RE field relocations, and `struct file`'s layout differs between
/// kernels (f_path moved around 6.12), so a compiled-in offset only works on some of
/// them. This lives in frozen .rodata, so the verifier sees it as a constant and still
/// accepts the resulting pointer as a `struct path *` for bpf_d_path.
#[unsafe(no_mangle)]
static FILE_F_PATH_OFFSET: u32 = 0;

// -EPERM: what we return to actually block the operation
const EPERM: i32 = -1;

#[repr(C)]
pub struct PathBuf {
    pub buf: [u8; PATH_SIZE],
}

// Scratch buffer for building the path
#[map(name = "path_scratch")]
static PATH_SCRATCH: PerCpuArray<PathBuf> = PerCpuArray::with_max_entries(1, 0);

// Process names ("comm") with list type indicator
// Key = 16-byte comm, Values = 1 (deny list), 2 (allow list), 255 (mode indicator)
#[map(name = "COMMS")]
static COMMS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(64, 0);

// List of filepaths to block the execution of syscalls on
// Key = 256 byte filepath, Value = 1 (or 0 for placeholder stating it was not provided)
#[map(name = "BLOCKED_PATHS")]
static BLOCKED_PATHS: HashMap<[u8; 256], u8> = HashMap::with_max_entries(64, 0);

// System-wide (BPF_LSM_MAC) LSM programs return 0 to allow or a negative errno (-EPERM
// here) to deny. Cgroup-scoped (BPF_LSM_CGROUP) programs use the cgroup-BPF convention
// instead: 1 allows and 0 denies (the kernel turns 0 into -EPERM), and the verifier
// rejects any other value. Note this is the reverse of the system-wide 0 = allow.
// should_block_open/should_block_execve return the shared deny decision as a plain bool;
// each #[lsm]/#[lsm_cgroup] wrapper translates it into its attach type's convention.
#[lsm(hook = "file_open")]
pub fn block_open(ctx: LsmContext) -> i32 {
    if should_block_open(ctx) { EPERM } else { 0 }
}

// Cgroup-scoped equivalent of block_open above, for --cgroup: identical logic (and the
// same COMMS/BLOCKED_PATHS maps), but a separate program because the eBPF-side
// attachment mechanism (BPF_LSM_CGROUP vs BPF_LSM_MAC) requires its own macro/section,
// even though the two only ever differ in how userspace attaches them and in their
// return-value convention (see above).
#[lsm_cgroup(hook = "file_open")]
pub fn block_open_cgroup(ctx: LsmContext) -> i32 {
    if should_block_open(ctx) { 0 } else { 1 }
}

// Blocking a comm here can be narrowed to specific paths via BLOCKED_PATHS: if that
// list has real entries, a blocked comm is only denied for opens matching one of
// those paths (see the is_path_map_empty/path_is_blocked check below) - e.g. "block
// vim from opening /etc/shadow" rather than "block vim from opening anything". With
// no path list configured (just the placeholder), a blocked comm is denied for every
// open. This is deliberately different from block_execve below, which has no such
// narrowing: a blocked comm can never execute at all, full stop - blocking specific
// paths doesn't apply to "should this binary be allowed to run".
fn should_block_open(ctx: LsmContext) -> bool {
    // Check if this comm should be blocked based on allow/deny lists
    if !comm_is_blocked() {
        return false;
    }

    let f: *const u8 = ctx.arg(0);

    let Some(ptr) = PATH_SCRATCH.get_ptr_mut(0) else {
        return true; // couldn't get scratch space, deny by default
    };
    let scratch = unsafe { &mut *ptr };
    // Zero first: bpf_d_path writes the path plus a NUL and leaves the rest of the
    // buffer untouched, so after this the buffer is exactly the zero-padded key format
    // userspace uses for BLOCKED_PATHS and can be looked up directly. (Copying a
    // variable-length path into a separate stack key is rejected by the verifier as an
    // unbounded variable-offset stack write.)
    scratch.buf = [0u8; PATH_SIZE];

    // read_volatile so the compiler can't fold in the placeholder 0 at build time
    let f_path_offset = unsafe { core::ptr::read_volatile(&FILE_F_PATH_OFFSET) } as usize;
    let path_ptr = unsafe { f.add(f_path_offset) } as *mut core::ffi::c_void;

    #[cfg(bpf_target_arch = "aarch64")]
    let buf_ptr = scratch.buf.as_mut_ptr() as *mut u8;

    #[cfg(not(bpf_target_arch = "aarch64"))]
    let buf_ptr = scratch.buf.as_mut_ptr() as *mut i8;

    let ret: c_long = unsafe { bpf_d_path(path_ptr as *mut _, buf_ptr, PATH_SIZE as u32) };

    if ret > 0 {
        // If path map has real entries (not just placeholder) and this path isn't blocked, allow it
        if !is_path_map_empty() && !path_is_blocked(&scratch.buf) {
            return false; // comm is blocked but the path isn't, allow it
        }
    }

    // if we couldn't get the path, or path checking indicates block, deny by default
    true
}

// Hook for strictly blocking execve: unlike should_block_open above, a blocked comm is
// always denied here with no path-based narrowing.
#[lsm(hook = "bprm_check_security")]
pub fn block_execve(ctx: LsmContext) -> i32 {
    if should_block_execve(ctx) { EPERM } else { 0 }
}

// Cgroup-scoped equivalent of block_execve above, for --cgroup. See block_open_cgroup.
#[lsm_cgroup(hook = "bprm_check_security")]
pub fn block_execve_cgroup(ctx: LsmContext) -> i32 {
    if should_block_execve(ctx) { 0 } else { 1 }
}

fn should_block_execve(_ctx: LsmContext) -> bool {
    comm_is_blocked()
}

// Returns true if the current task's comm should be blocked.
// Logic:
// - If DENY_LIST mode: block if comm IS in the map
// - If ALLOW_LIST mode: block if comm is NOT in the map
fn comm_is_blocked() -> bool {
    match bpf_get_current_comm() {
        Ok(comm) => {
            match unsafe { COMMS.get(&comm) } {
                Some(&value) => {
                    // Found the comm in the map
                    if value == DENY_LIST {
                        // Deny list mode: block because it's in the deny list
                        true
                    } else if value == ALLOW_LIST {
                        // Allow list mode: don't block because it's in the allow list
                        false
                    } else {
                        // No list specified, default to not blocking
                        false
                    }
                }
                None => {
                    // Comm not in map, so we do not have a key to go off and must use the LIST_MODE indicator in the hashmap
                    let list_mode = get_list_mode();

                    if list_mode == ALLOW_LIST {
                        // Allow list mode: block because comm is NOT in the allow list
                        true
                    } else {
                        // Deny list mode: don't block because comm is NOT in the deny list
                        false
                    }
                }
            }
        }
        Err(_) => false,
    }
}

// Determine the list mode by checking the mode indicator key
// Returns DENY_LIST or ALLOW_LIST
fn get_list_mode() -> u8 {
    // Use a mode indicator key that userspace sets to indicate the mode
    let mode_key: [u8; 16] = [LIST_MODE; 16];

    match unsafe { COMMS.get(&mode_key) } {
        Some(&value) => value,
        None => DENY_LIST, // Default to deny list mode if mode key not found
    }
}

// Returns true if the provided file path is in the forbidden file list
// `path` is a NUL-terminated, zero-padded path buffer - the same layout userspace uses
// for BLOCKED_PATHS keys. Linux paths are arbitrary bytes, so this compares raw bytes.
fn path_is_blocked(path: &[u8; PATH_SIZE]) -> bool {
    unsafe { BLOCKED_PATHS.get(path).is_some() }
}

// Returns true if the path map only contains the placeholder (meaning it's effectively empty)
// The placeholder is an all-zeros key with value 0
fn is_path_map_empty() -> bool {
    let placeholder: [u8; 256] = [0u8; 256];
    match unsafe { BLOCKED_PATHS.get(&placeholder) } {
        Some(val) => *val == 0, // If placeholder exists with value 0, map is "empty"
        None => false,          // Placeholder doesn't exist, so map has real entries
    }
}
