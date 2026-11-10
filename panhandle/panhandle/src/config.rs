use std::path::PathBuf;

use panhandle_common::*;

/// UID filtering options written into the `uid_options`/`uid_include_list` maps of the
/// execve, readline, and zlentry programs (see `ebpf_loader::load_ebpf`). Maps rather
/// than load-time globals, so the filters stay adjustable after load.
#[derive(Clone, Copy, Debug, Default)]
pub struct PanhandleConfig {
    pub shells: u32,
    pub exclude_min_uid: u32,
    pub exclude_max_uid: u32,
    pub include_enabled: u32,
    pub include_uids: [u32; UID_COUNT],
}

/// Syscall-blocking options for `blocking::setup_syscall_blocking`, already validated
/// and resolved by main (allow/deny list mode resolved once, via
/// `helpers::resolve_comm_list_mode`).
#[derive(Debug, Clone, Default)]
pub struct BlockingConfig {
    pub syscalls: Vec<String>,
    /// NO_LIST, DENY_LIST, or ALLOW_LIST
    pub list_type: u8,
    pub comms: Vec<String>,
    pub block_paths: Vec<String>,
    /// Scope blocking to this cgroup v2 directory instead of system-wide (--cgroup).
    pub cgroup_path: Option<PathBuf>,
}
