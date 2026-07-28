use aya_ebpf::{
    cty::c_long,
    helpers::{bpf_d_path, bpf_get_current_comm},
    macros::{lsm, map},
    maps::{HashMap, PerCpuArray},
    programs::LsmContext,
};
use aya_log_ebpf::info;

use crate::vmlinux::file;

const PATH_SIZE: usize = 256;
const PATH_MASK: usize = PATH_SIZE - 1;

// -EPERM: what we return to actually block the operation, any negative number works
const EPERM: i32 = -1;

#[repr(C)]
pub struct PathBuf {
    pub buf: [u8; PATH_SIZE],
}

// Scratch buffer for building the path
#[map(name = "path_scratch")]
static PATH_SCRATCH: PerCpuArray<PathBuf> = PerCpuArray::with_max_entries(1, 0);

// Denylist of process names ("comm"), populated from userspace.
// Key = 16-byte comm, Value = 1
#[map(name = "BLOCKED_COMMS")]
static BLOCKED_COMMS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(64, 0);

// List of filepaths to blocked the execution of syscalls on
// Key = 256 byte filepath, Value = 1
#[map(name = "BLOCKED_PATHS")]
static BLOCKED_PATHS: HashMap<[u8; 256], u8> = HashMap::with_max_entries(64,0);

#[lsm(hook = "file_open")]
pub fn block_open(ctx: LsmContext) -> i32 {
    match try_block_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_block_open(ctx: LsmContext) -> Result<i32, i32> {
    // Only act on denylisted processes.
    if !comm_is_blocked() {
        return Ok(0);
    }

    let f: *const file = ctx.arg(0);

    let ptr = PATH_SCRATCH.get_ptr_mut(0).ok_or(0i32)?;
    let scratch = unsafe { &mut *ptr };

    let path_ptr = unsafe { &(*f).f_path } as *const _ as *mut core::ffi::c_void;

    let ret: c_long = unsafe {
        bpf_d_path(
            path_ptr as *mut _,
            scratch.buf.as_mut_ptr() as *mut i8,
            PATH_SIZE as u32,
        )
    };

    if ret > 0 {
        let len = (ret as usize) & PATH_MASK;
        let path_str = unsafe { core::str::from_utf8_unchecked(&scratch.buf[..len]) };
        if !path_is_blocked(&path_str) {
            return Ok(0); // comm is blocked, but path isn't, so return Ok
        }
    }

    // Deny the open.
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

unsafe fn try_block_execve(ctx: LsmContext) -> Result<i32, i32> {
    if !comm_is_blocked() {
        return Ok(0);
    }
    Ok(EPERM)
}

// Returns true if the current task's comm is in the denylist.
fn comm_is_blocked() -> bool {
    match bpf_get_current_comm() {
        Ok(comm) => unsafe { BLOCKED_COMMS.get(&comm).is_some() },
        Err(_) => false,
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
