use aya_ebpf::{
    cty::c_long,
    helpers::{bpf_d_path, bpf_get_current_comm},
    macros::{lsm, map},
    maps::{HashMap, PerCpuArray},
    programs::LsmContext,
};

// use aya_log_ebpf::info;
use crate::vmlinux::file;

const PATH_SIZE: usize = 256;
const PATH_MASK: usize = PATH_SIZE - 1;

// Import from common lib
const DENY_LIST: u8 = 1;
const ALLOW_LIST: u8 = 2;
const LIST_MODE: u8 = 255;

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

#[lsm(hook = "file_open")]
pub fn block_open(ctx: LsmContext) -> i32 {
    match try_block_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_block_open(ctx: LsmContext) -> Result<i32, i32> {
    // Check if this comm should be blocked based on allow/deny lists
    if !comm_is_blocked() {
        return Ok(0);
    }

    let f: *const file = unsafe { ctx.arg(0) };

    let ptr = PATH_SCRATCH.get_ptr_mut(0).ok_or(0i32)?;
    let scratch = unsafe { &mut *ptr };

    let path_ptr = unsafe { &(*f).f_path } as *const _ as *mut core::ffi::c_void;

    #[cfg(target_arch = "aarch64")]
    let buf_ptr = scratch.buf.as_mut_ptr() as *mut u8;
    #[cfg(not(target_arch = "aarch64"))]
    let buf_ptr = scratch.buf.as_mut_ptr() as *mut i8;

    let ret: c_long = unsafe {
        bpf_d_path(
            path_ptr as *mut _,
            buf_ptr,
            PATH_SIZE as u32,
        )
    };

    if ret > 0 {
        let len = (ret as usize) & PATH_MASK;
        let path_str = unsafe { core::str::from_utf8_unchecked(&scratch.buf[..len]) };

        // If path map has real entries (not just placeholder) and this path isn't blocked, allow it
        if !is_path_map_empty() && !path_is_blocked(&path_str) {
            return Ok(0); // comm is blocked but the path isn't, return ok
        }
    }

    // if we couldn't get the path, or path checking indicates block, deny by default
    Ok(EPERM)
}

// hook for strictly blocking execve
#[lsm(hook = "bprm_check_security")]
pub fn block_execve(ctx: LsmContext) -> i32 {
    match unsafe { try_block_execve(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_block_execve(_ctx: LsmContext) -> Result<i32, i32> {
    if !comm_is_blocked() {
        return Ok(0);
    }
    Ok(EPERM)
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
fn path_is_blocked(filepath: &str) -> bool {
    let mut key: [u8; 256] = [0u8; 256];
    let path_bytes = filepath.as_bytes();
    let len = path_bytes.len().min(256);
    key[..len].copy_from_slice(&path_bytes[..len]);
    unsafe { BLOCKED_PATHS.get(&key).is_some() }
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
