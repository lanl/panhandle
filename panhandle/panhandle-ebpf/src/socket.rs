use aya_ebpf::{
    macros::map,
    maps::HashMap,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_comm},
};
use panhandle_common::SocketStats;
//use aya_log_ebpf::info;

#[map(name = "tcp_socket_count")]
static mut TCP_SOCKET_COUNT: HashMap<u32, SocketStats> = HashMap::with_max_entries(1024, 0);

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
    const TCP_ESTABLISHED: i32 = 1;
    const TCP_CLOSE: i32 = 7;

    let newstate: i32 = unsafe { ctx.arg(2) };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if newstate == TCP_ESTABLISHED {
        // Get existing stats or create new
        let mut stats = unsafe { 
            TCP_SOCKET_COUNT.get(&pid).copied().unwrap_or(SocketStats { 
                count: 0, 
                comm: [0; 16] 
            }) 
        };

        stats.count += 1;
        
        // Update process name (handles new PIDs or re-used PIDs)
        unsafe { 
            let _ = bpf_get_current_comm(&mut stats.comm); 
        }

        unsafe { 
            TCP_SOCKET_COUNT.insert(&pid, &stats, 0).map_err(|_| 1u32)? 
        };
    } 
    else if newstate == TCP_CLOSE {
        // Look up the record; if it exists, decrement the count
        if let Some(stats) = unsafe { TCP_SOCKET_COUNT.get_ptr_mut(&pid) } {
            unsafe {
                if (*stats).count > 0 {
                    (*stats).count -= 1;
                }

                // Remove entry if count hits 0 to keep the map clean
                if (*stats).count == 0 {
                    let _ = TCP_SOCKET_COUNT.remove(&pid);
                }
            }
        }
    }

    Ok(0)
}
