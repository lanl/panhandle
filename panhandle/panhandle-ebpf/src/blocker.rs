use aya_ebpf::{
    helpers::bpf_get_current_comm,
    macros::{lsm, map}, 
    maps::HashMap, 
    programs::LsmContext
};

#[map(name = "BLOCKED_COMMS")]
pub static BLOCKED_COMMS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(1024, 0);

/// Block file open operations for blocked comms
#[lsm(hook = "file_open")]
pub fn block_open(ctx: LsmContext) -> i32 {
    match try_block_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_block_open(_ctx: LsmContext) -> Result<i32, i32> {
    let comm = bpf_get_current_comm().map_err(|_| -1)?;

    unsafe {
        // block the file open if it is in the blacklist
        if BLOCKED_COMMS.get(&comm).is_some() {
            return Ok(-13); // -EACCES
        }
    }
    
    Ok(0)
}

// Block execve operations for blocked comms
#[lsm(hook = "bprm_check_security")]
pub fn block_execve(ctx: LsmContext) -> i32 {
    match try_block_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_block_execve(_ctx: LsmContext) -> Result<i32, i32> {
    let comm = bpf_get_current_comm().map_err(|_| -1)?;

    unsafe {
        // check if current comm is blocked
        if BLOCKED_COMMS.get(&comm).is_some() {
            return Ok(-13); // -EACCES
        }
    }

    Ok(0)
}