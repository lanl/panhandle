#![no_std]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::comparison_chain)]
// used code from https://github.com/FlakM/sysrat/blob/main/ebpf/common/src/lib.rs
use core::fmt::{self, Formatter};

// put all the desired shared constants here / enables not adding them to the ebpf
// memory-limited application and also re-use in the userland application.
pub const ARG_SIZE: usize = 400;
pub const ARG_COUNT: usize = 20;
pub const UID_COUNT: usize = 10;
pub const ENV_SIZE: usize = 120;
pub const ENV_COUNT: usize = 20;
pub const EXECUTABLE_COUNT: usize = 20;
pub const MINUID: u32 = 0;
pub const MAXUID: u32 = 999;
pub const LEN_MAX_PATH: usize = 1024;
pub const FILENAME_OFFSET: usize = 16;
pub const NO_LIST: u8 = 0;
pub const DENY_LIST: u8 = 1;
pub const ALLOW_LIST: u8 = 2;
pub const LIST_MODE: u8 = 255;

// Process blocking limits
pub const MAX_PATH_LENGTH: usize = 255;
pub const MAX_COMM_LENGTH: usize = 15;
pub const MAX_BLOCKED_PATHS: usize = 64;
pub const MAX_BLOCKED_COMMS: usize = 64;

// Keys into the uid_options / readline_uid_options / zlentry_uid_options maps, shared
// between userspace (which populates them, main.rs) and eBPF (which reads them via
// get_bool/get_uid, main.rs and shell_entry.rs). UID_OPT_SHELLS only means anything to
// the execve probe; the other three are read by all three probes.
pub const UID_OPT_SHELLS: u32 = 0;
pub const UID_OPT_EXCLUDE_MIN: u32 = 1;
pub const UID_OPT_EXCLUDE_MAX: u32 = 2;
pub const UID_OPT_INCLUDE_ENABLED: u32 = 3;

// structs used for consuming or presenting the desired data
// this readline struct is used by the zlentry and readline methods
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Readline {
    pub timestamp: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub tgid: u32,
    pub command: [u8; 16],
    pub entry: [u8; ARG_SIZE],
}

impl Readline {
    /// Creates a new `Readline` instance for testing or construction.
    ///
    /// # Example
    ///
    /// ```
    /// use panhandle_common::{Readline, ARG_SIZE};
    ///
    /// let mut rl = Readline {
    ///     timestamp: 1_000_000_000,
    ///     uid: 1000,
    ///     gid: 1000,
    ///     pid: 42,
    ///     tgid: 42,
    ///     command: [0; 16],
    ///     entry: [0; ARG_SIZE],
    /// };
    /// rl.command[..4].copy_from_slice(b"bash");
    /// rl.entry[..5].copy_from_slice(b"ls -l");
    /// assert_eq!(rl.uid, 1000);
    /// ```
    pub fn new_for_test() -> Self {
        Self {
            timestamp: 0,
            uid: 0,
            gid: 0,
            pid: 0,
            tgid: 0,
            command: [0; 16],
            entry: [0; ARG_SIZE],
        }
    }
}

// Custom struct used for monitoring network usage
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct NetStats {
    // TCP connection state counts of sockets per PID
    pub tcp_established: u32,
    pub tcp_syn_recv: u32,
    pub tcp_close_wait: u32,
    pub tcp_time_wait: u32,
    pub tcp_fin_wait: u32,

    // UDP
    pub udp_sockets: u32, // treated as a flag variable for if a udp message has been sent from the socket

    // Network I/O counters
    pub bytes_sent: u64,   // total bytes sent through this socket
    pub bytes_recv: u64,   // total bytes received through this socket
    pub packets_sent: u64, // total packets sent through this socket
    pub packets_recv: u64, // total packets received through this socket
}

impl NetStats {
    /// Create a new `NetStats` instance with all fields initialized to zero.
    ///
    /// # Example
    ///
    /// ```
    /// use panhandle_common::NetStats;
    ///
    /// let stats = NetStats::new();
    /// assert_eq!(stats.tcp_established, 0);
    /// assert_eq!(stats.bytes_sent, 0);
    /// assert!(!stats.has_activity());
    /// ```
    pub const fn new() -> Self {
        Self {
            tcp_established: 0,
            tcp_syn_recv: 0,
            tcp_close_wait: 0,
            tcp_time_wait: 0,
            tcp_fin_wait: 0,
            udp_sockets: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            packets_sent: 0,
            packets_recv: 0,
        }
    }

    /// Check if this `NetStats` entry has any activity worth reporting.
    ///
    /// Returns `true` if there are any active connections or data transfer.
    ///
    /// # Example
    ///
    /// ```
    /// use panhandle_common::NetStats;
    ///
    /// let mut stats = NetStats::new();
    /// assert!(!stats.has_activity());
    ///
    /// stats.tcp_established = 1;
    /// assert!(stats.has_activity());
    ///
    /// let mut stats2 = NetStats::new();
    /// stats2.bytes_sent = 100;
    /// assert!(stats2.has_activity());
    /// ```
    pub const fn has_activity(&self) -> bool {
        self.tcp_established > 0
            || self.tcp_syn_recv > 0
            || self.tcp_close_wait > 0
            || self.tcp_time_wait > 0
            || self.tcp_fin_wait > 0
            || self.udp_sockets > 0
            || self.bytes_sent > 0
            || self.bytes_recv > 0
            || self.packets_sent > 0
            || self.packets_recv > 0
    }
}

// Default trait implementation
impl Default for NetStats {
    fn default() -> Self {
        Self::new()
    }
}

/// A single delta reported by one of the socket kprobes/tracepoints for one PID.
/// Sent over a ring buffer rather than accumulated in a kernel-side map: each probe
/// invocation is stateless (no read-modify-write of shared map state, so no cross-CPU
/// race), and userspace folds these deltas into its own per-PID `NetStats` accumulator.
/// Most fields are zero on any given event; only the field(s) relevant to whichever
/// probe fired are set.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketStatsEvent {
    pub pid: u32,
    pub tcp_established_delta: i32,
    pub tcp_syn_recv_delta: i32,
    pub tcp_close_wait_delta: i32,
    pub tcp_time_wait_delta: i32,
    pub tcp_fin_wait_delta: i32,
    // Not a delta: UDP is connectionless, so this is a one-way "seen a UDP socket for
    // this pid" flag (1) applied via max(), mirroring NetStats::udp_sockets.
    pub udp_sockets_set: u8,
    pub bytes_sent_delta: u64,
    pub bytes_recv_delta: u64,
    pub packets_sent_delta: u64,
    pub packets_recv_delta: u64,
}

impl SocketStatsEvent {
    /// Create a new `SocketStatsEvent` for the given PID with all deltas zeroed.
    ///
    /// # Example
    ///
    /// ```
    /// use panhandle_common::SocketStatsEvent;
    ///
    /// let event = SocketStatsEvent::new(1234);
    /// assert_eq!(event.pid, 1234);
    /// assert_eq!(event.tcp_established_delta, 0);
    /// assert_eq!(event.bytes_sent_delta, 0);
    /// ```
    pub const fn new(pid: u32) -> Self {
        Self {
            pid,
            tcp_established_delta: 0,
            tcp_syn_recv_delta: 0,
            tcp_close_wait_delta: 0,
            tcp_time_wait_delta: 0,
            tcp_fin_wait_delta: 0,
            udp_sockets_set: 0,
            bytes_sent_delta: 0,
            bytes_recv_delta: 0,
            packets_sent_delta: 0,
            packets_recv_delta: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SysEnterExecve {
    // Tracepoint header fields.
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    // Additional syscall-specific field.
    pub __syscall_nr: i32,
    // Execve-specific fields:
    pub command: *const u8,
    pub argv: *const *const u8,
    pub envp: *const *const u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecveEvent {
    pub timestamp: u64, // nanoseconds since boot
    pub argv: [[u8; ARG_SIZE]; ARG_COUNT],
    pub envp: [[u8; ENV_SIZE]; ENV_COUNT],
    pub pid: u32,
    pub gid: u32,
    pub uid: u32,
    pub tgid: u32,
    pub command: [u8; 16], // this can never be anything but per the method docs, hence hard-coded
    pub filename: [u8; LEN_MAX_PATH],
}

impl ExecveEvent {
    /// Creates a new `ExecveEvent` instance for testing or construction.
    ///
    /// # Example
    ///
    /// ```
    /// use panhandle_common::{ExecveEvent, ARG_SIZE, ARG_COUNT, ENV_SIZE, ENV_COUNT, LEN_MAX_PATH};
    ///
    /// let mut ev = ExecveEvent {
    ///     timestamp: 1_000_000_000,
    ///     argv: [[0; ARG_SIZE]; ARG_COUNT],
    ///     envp: [[0; ENV_SIZE]; ENV_COUNT],
    ///     pid: 42,
    ///     gid: 1000,
    ///     uid: 1000,
    ///     tgid: 42,
    ///     command: [0; 16],
    ///     filename: [0; LEN_MAX_PATH],
    /// };
    /// ev.filename[..7].copy_from_slice(b"/bin/ls");
    /// ev.argv[0][..5].copy_from_slice(b"ls -l");
    /// assert_eq!(ev.pid, 42);
    /// ```
    pub fn new_for_test() -> Self {
        Self {
            timestamp: 0,
            argv: [[0; ARG_SIZE]; ARG_COUNT],
            envp: [[0; ENV_SIZE]; ENV_COUNT],
            pid: 0,
            gid: 0,
            uid: 0,
            tgid: 0,
            command: [0; 16],
            filename: [0; LEN_MAX_PATH],
        }
    }
}

// trait implementations
// reduces code in the userland ebpf application while enabling debugging
impl core::fmt::Display for Readline {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "entry: {}, command: {}, uid: {}, pid: {}, gid: {}, tgid: {}",
            core::str::from_utf8(&self.entry)
                .unwrap_or_default()
                .trim_end_matches("\0")
                .trim(),
            core::str::from_utf8(&self.command)
                .unwrap_or_default()
                .trim_end_matches("\0")
                .trim(),
            self.uid,
            self.pid,
            self.gid,
            self.tgid
        )?;
        Ok(())
    }
}

impl core::fmt::Debug for ExecveEvent {
    // include envs and args
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{\"filename\": \"{}\", \"command\": \"{}\", \"uid\": \"{}\", \"pid\": \"{}\", \"gid\": \"{}\", \"tgid\": \"{}\", ",
            core::str::from_utf8(&self.filename)
                .unwrap_or_default()
                .trim_end_matches('\0')
                .trim(),
            core::str::from_utf8(&self.command)
                .unwrap_or_default()
                .trim_end_matches('\0')
                .trim(),
            self.uid,
            self.pid,
            self.gid,
            self.tgid
        )?;
        // eBPF zero-fills unused scratch slots; an empty or NUL-prefixed entry ends the list.
        write!(f, "\"args\": [")?;
        let mut first = true;
        for arg in &self.argv {
            let arg = core::str::from_utf8(arg)
                .unwrap_or_default()
                .trim_end_matches('\0')
                .trim();
            if arg.is_empty() || arg.starts_with('\0') {
                break;
            }
            if !first {
                write!(f, ", ")?;
            }
            write!(f, "\"{arg}\"")?;
            first = false;
        }
        write!(f, "], \"envs\": [")?;
        let mut first = true;
        for env in &self.envp {
            let env = core::str::from_utf8(env)
                .unwrap_or_default()
                .trim_end_matches('\0')
                .trim();
            if env.is_empty() || env.starts_with('\0') {
                break;
            }
            if !first {
                write!(f, ", ")?;
            }
            write!(f, "\"{env}\"")?;
            first = false;
        }
        write!(f, "]}}")?;
        Ok(())
    }
}

impl core::fmt::Display for ExecveEvent {
    // include envs and args
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "filename: {}, command: {}, uid: {}, pid: {}, gid: {}, tgid: {}, ",
            core::str::from_utf8(&self.filename)
                .unwrap_or_default()
                .trim_end_matches('\0')
                .trim(),
            core::str::from_utf8(&self.command)
                .unwrap_or_default()
                .trim_end_matches('\0')
                .trim(),
            self.uid,
            self.pid,
            self.gid,
            self.tgid
        )?;
        write!(f, "args: [")?;
        for arg in &self.argv {
            let arg = core::str::from_utf8(arg)
                .unwrap_or_default()
                .trim_end_matches('\0')
                .trim();
            if !arg.is_empty() && !arg.starts_with('\0') {
                write!(f, "{arg},")?;
            }
        }
        write!(f, "], envs: [")?;
        for env in &self.envp {
            let env = core::str::from_utf8(env)
                .unwrap_or_default()
                .trim_end_matches('\0')
                .trim();
            if !env.is_empty() && !env.starts_with('\0') {
                write!(f, "{env},")?;
            }
        }
        write!(f, "]")?;
        Ok(())
    }
}
