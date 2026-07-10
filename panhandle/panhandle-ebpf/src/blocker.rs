use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{lsm, map},
    maps::HashMap,
    programs::LsmContext,
};

// Explicitly set the map name to match userspace
#[map(name = "BLOCKED_PIDS")]
pub static BLOCKED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[lsm(hook = "file_open")]
pub fn block_open(ctx: LsmContext) -> i32 {
    match try_block_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_block_open(_ctx: LsmContext) -> Result<i32, i32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    
    unsafe {
        if BLOCKED_PIDS.get(&pid).is_some() {
            return Ok(-13); // -EACCES
        }
    }
    
    Ok(0)
}