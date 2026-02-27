#![no_std]
#![allow(non_snake_case)]
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
#[derive(Debug, Clone, Copy)]
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
