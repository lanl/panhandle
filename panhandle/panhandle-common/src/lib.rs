#![no_std]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::comparison_chain)]
// used code from https://github.com/FlakM/sysrat/blob/main/ebpf/common/src/lib.rs
use core::fmt::{self, Formatter};
pub type pid_t = i32;

// put all the desired shared constants here / enables not adding them to the ebpf
// memory-limited application and also re-use in the userland application.
pub const ARG_SIZE: usize = 400;
pub const ARG_COUNT: usize = 20;
pub const UID_COUNT: usize = 10;
pub const ENV_SIZE: usize = 120;
pub const ENV_COUNT: usize = 20;
pub const EXECUTABLE_COUNT: usize = 20;
pub const MINUID: u32 = 1;
pub const MAXUID: u32 = 999;
pub const LEN_MAX_PATH: usize = 1024;
pub const SYSCALL_OFFSET: usize = 8;
pub const FILENAME_OFFSET: usize = 16;
pub const ARGS_OFFSET: usize = 24;
pub const MAX_POSSIBLE_UID: u32 = 4294967294;

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
    //pub regs: [u64; 31],
    //pub task: *const task_struct,
    //pub fp: [u8; ARG_SIZE],
}

// this sched switch struct is used for calculating CPU usage
// replaced aya_ebpf data types in place of Rust ones to prevent seg fault issue when reading the sched switch kernel struct
// see cat /sys/kernel/debug/tracing/events/sched/sched_switch/format to verify the size and signage of the data types
#[repr(C)]
pub struct trace_event_raw_sched_switch {
    pub ent: trace_entry,
    pub prev_comm: [i8; 16],  // Changed from ::aya_ebpf::cty::c_char
    pub prev_pid: pid_t,
    pub prev_prio: i32,        // Changed from ::aya_ebpf::cty::c_int
    pub prev_state: i64,       // Changed from ::aya_ebpf::cty::c_long
    pub next_comm: [i8; 16],
    pub next_pid: pid_t,
    pub next_prio: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct trace_entry {
    pub type_: u16,           // Changed from ::aya_ebpf::cty::c_ushort
    pub flags: u8,            // Changed from ::aya_ebpf::cty::c_uchar
    pub preempt_count: u8,
    pub pid: i32,             // Changed from ::aya_ebpf::cty::c_int
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
                .trim(),
            core::str::from_utf8(&self.command)
                .unwrap_or_default()
                .trim(),
            self.uid,
            self.pid,
            self.gid,
            self.tgid
        )?;
        let mut item_count = 0;
        write!(f, "\"args\": [")?;
        for arg in &self.argv {
            let arg = core::str::from_utf8(arg).unwrap_or_default().trim();
            if arg.chars().nth(0).unwrap() != '\0' {
                item_count += 1;
            } else {
                break;
            }
        }
        let mut index = 0;
        for arg in &self.argv {
            let arg = core::str::from_utf8(arg).unwrap_or_default().trim();
            if index < item_count - 1 {
                write!(f, "\"{arg}\", ")?;
            } else if index == item_count - 1 {
                write!(f, "\"{arg}\"")?;
            } else {
                break;
            }
            index += 1;
        }
        index = 0;
        item_count = 0;
        write!(f, "], \"envs\": [")?;
        for env in &self.envp {
            let env = core::str::from_utf8(env).unwrap_or_default().trim();
            if env.chars().nth(0).unwrap() != '\0' {
                item_count += 1;
            } else {
                break;
            }
        }
        for env in &self.envp {
            let env = core::str::from_utf8(env).unwrap_or_default().trim();
            if index < item_count - 1 {
                write!(f, "\"{}\", ", env.trim())?;
            } else if index == item_count - 1 {
                write!(f, "\"{}\"", env.trim())?;
            } else {
                break;
            }
            index += 1;
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
                .trim(),
            core::str::from_utf8(&self.command)
                .unwrap_or_default()
                .trim(),
            self.uid,
            self.pid,
            self.gid,
            self.tgid
        )?;
        write!(f, "args: [")?;
        for arg in &self.argv {
            let arg = core::str::from_utf8(arg).unwrap_or_default().trim();
            if arg.chars().nth(0).unwrap() != '\0' {
                write!(f, "{},", arg.trim())?;
            }
        }
        write!(f, "], envs: [")?;
        for env in &self.envp {
            let env = core::str::from_utf8(env).unwrap_or_default().trim();
            if env.chars().nth(0).unwrap() != '\0' {
                write!(f, "{},", env.trim())?;
            }
        }
        write!(f, "]")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SocketStats {
    pub count: u32,
    pub comm: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InetSockSetState {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub common_preempt_lazy_count: u8,
    _padding: [u8; 7], // Alignment to offset 16
    pub skaddr: *const core::ffi::c_void,
    pub oldstate: i32,
    pub newstate: i32,
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub protocol: u16,
    pub saddr: [u8; 4],
    pub daddr: [u8; 4],
    pub saddr_v6: [u8; 16],
    pub daddr_v6: [u8; 16],
}
