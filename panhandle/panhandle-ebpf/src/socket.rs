use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::map,
    maps::HashMap,
};
//use aya_log_ebpf::info;

#[map(name = "tcp_socket_count")]
static mut TCP_SOCKET_COUNT: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

const TCP_ESTABLISHED: i32 = 1;
const TCP_CLOSE: i32 = 7;

use aya_ebpf::{macros::btf_tracepoint, programs::BtfTracePointContext};

// Using #[btf_tracepoint] instead of #[tracepoint]
#[btf_tracepoint(function = "inet_sock_set_state")]
pub fn inet_sock_set_state(ctx: BtfTracePointContext) -> u32 {
    let _ = try_inet_sock_set_state(ctx);
    0
}

fn try_inet_sock_set_state(ctx: BtfTracePointContext) -> Result<u32, u32> {
    let newstate: i32 = unsafe { ctx.arg(2) };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    //let pcomm: [u8; 16];

    if newstate == TCP_ESTABLISHED {
        // Get process name (handles new PIDs or re-used PIDs)
        //pcomm = bpf_get_current_comm().unwrap();
        // Get existing stats or create new
        let mut count = unsafe {
            TCP_SOCKET_COUNT.get(&pid).copied().unwrap_or(0)
        };

        count += 1;

        unsafe { TCP_SOCKET_COUNT.insert(&pid, &count, 0).map_err(|_| 1u32)? };
    } else if newstate == TCP_CLOSE {
        // Look up the record; if it exists, decrement the count
        if let Some(count) = unsafe { TCP_SOCKET_COUNT.get_ptr_mut(&pid) } {
            unsafe {
                if (*count) > 0 {
                    (*count) -= 1;
                }

                // Remove entry if count hits 0 to keep the map clean
                if (*count) == 0 {
                    let _ = TCP_SOCKET_COUNT.remove(&pid);
                }
            }
        }
    }

    Ok(0)
}
