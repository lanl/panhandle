use aya_ebpf::{helpers::bpf_get_current_pid_tgid, macros::map, maps::HashMap};
//use aya_log_ebpf::info;

// State counters
#[map(name = "tcp_established_count")]
static mut TCP_ESTABLISHED_COUNT: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map(name = "tcp_syn_recv_count")]
static mut TCP_SYN_RECV_COUNT: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map(name = "tcp_close_wait_count")]
static mut TCP_CLOSE_WAIT_COUNT: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map(name = "tcp_time_wait_count")]
static mut TCP_TIME_WAIT_COUNT: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map(name = "tcp_fin_wait_count")]
static mut TCP_FIN_WAIT_COUNT: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map(name = "udp_socket_count")]
static mut UDP_SOCKET_COUNT: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

// useful TCP states matching the struct in the kernel
const TCP_ESTABLISHED: i32 = 1;
const TCP_SYN_RECV: i32 = 3;
const TCP_FIN_WAIT1: i32 = 4;
const TCP_FIN_WAIT2: i32 = 5;
const TCP_TIME_WAIT: i32 = 6;
const TCP_CLOSE_WAIT: i32 = 8;

use aya_ebpf::{macros::btf_tracepoint, programs::BtfTracePointContext};

// Using #[btf_tracepoint] instead of #[tracepoint]
#[btf_tracepoint(function = "inet_sock_set_state")]
pub fn inet_sock_set_state(ctx: BtfTracePointContext) -> u32 {
    let _ = try_inet_sock_set_state(ctx);
    0
}

// helper macro for updating state counts
// increments/decrements the count of the corresponding state's hashmap
// "state" is the state we are currently checking in the macro, it is not necessarily the new state
macro_rules! track_state {
    ($map:ident, $oldstate:expr, $newstate:expr, $state:expr, $pid:expr) => {
        // entering this state, increment its count
        if $newstate == $state {
            let mut count = unsafe { $map.get(&$pid).copied().unwrap_or(0) };
            count += 1;
            let _ = unsafe { $map.insert(&$pid, &count, 0) };
        }
        // exiting this state, decrement its count
        else if $oldstate == $state && $newstate != $state {
            if let Some(count) = unsafe { $map.get_ptr_mut(&$pid) } {
                unsafe {
                    if *count > 0 {
                        *count -= 1;
                    }
                    if *count == 0 {
                        let _ = $map.remove(&$pid);
                    }
                }
            }
        }
    };
}
fn try_inet_sock_set_state(ctx: BtfTracePointContext) -> Result<u32, u32> {
    let oldstate: i32 = unsafe { ctx.arg(1) };
    let newstate: i32 = unsafe { ctx.arg(2) };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    //let pcomm: [u8; 16];

    // check all important states and update map counts
    track_state!(
        TCP_ESTABLISHED_COUNT,
        oldstate,
        newstate,
        TCP_ESTABLISHED,
        pid
    );
    track_state!(TCP_SYN_RECV_COUNT, oldstate, newstate, TCP_SYN_RECV, pid);
    track_state!(
        TCP_CLOSE_WAIT_COUNT,
        oldstate,
        newstate,
        TCP_CLOSE_WAIT,
        pid
    );
    track_state!(TCP_TIME_WAIT_COUNT, oldstate, newstate, TCP_TIME_WAIT, pid);
    track_state!(TCP_FIN_WAIT_COUNT, oldstate, newstate, TCP_FIN_WAIT1, pid);
    track_state!(TCP_FIN_WAIT_COUNT, oldstate, newstate, TCP_FIN_WAIT2, pid);

    Ok(0)
}
