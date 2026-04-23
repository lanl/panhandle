use aya_ebpf::{
    EbpfContext,
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
//use aya_log_ebpf::info;
use panhandle_common::InetSockSetState;

#[map]
static mut TCP_SOCKET_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

const TCP_ESTABLISHED: i32 = 1;
const TCP_CLOSE: i32 = 7;

#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    match try_inet_sock_set_state(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_inet_sock_set_state(ctx: TracePointContext) -> Result<u32, u32> {
    let data: &InetSockSetState = unsafe {
        match ctx.read_at(0) {
            Ok(d) => d,
            Err(_) => return Err(1),
        }
    };

    let pid = ctx.tgid();

    // Increment count on established
    if data.newstate == TCP_ESTABLISHED {
        let count = unsafe { TCP_SOCKET_COUNT.get(&pid).unwrap_or(&0) };
        let new_count = count + 1;
        unsafe {
            let _ = TCP_SOCKET_COUNT.insert(&pid, &new_count, 0);
        }
    }
    // Decrement count on close
    // Check oldstate to ensure we only decrement for tracked active connections
    else if data.newstate == TCP_CLOSE {
        if let Some(count) = unsafe { TCP_SOCKET_COUNT.get_ptr_mut(&pid) } {
            unsafe {
                if *count > 0 {
                    *count -= 1;
                }
                // Cleanup map if count hits zero to save space
                if *count == 0 {
                    let _ = TCP_SOCKET_COUNT.remove(&pid);
                }
            }
        }
    }

    Ok(0)
}
