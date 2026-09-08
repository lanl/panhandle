//! Tests for panhandle-common library

use std::mem::{offset_of, size_of};

use panhandle_common::*;

#[test]
fn test_constants() {
    assert_eq!(ARG_SIZE, 400);
    assert_eq!(ARG_COUNT, 20);
    assert_eq!(UID_COUNT, 10);
    assert_eq!(ENV_SIZE, 120);
    assert_eq!(ENV_COUNT, 20);
    assert_eq!(EXECUTABLE_COUNT, 20);
    assert_eq!(MINUID, 0);
    assert_eq!(MAXUID, 999);
    assert_eq!(LEN_MAX_PATH, 1024);
    assert_eq!(FILENAME_OFFSET, 16);
    assert_eq!(NO_LIST, 0);
    assert_eq!(DENY_LIST, 1);
    assert_eq!(ALLOW_LIST, 2);
    assert_eq!(LIST_MODE, 255);
}

#[test]
fn test_netstats_new_zeroed() {
    let s = NetStats::new();
    assert_eq!(s.tcp_established, 0);
    assert_eq!(s.bytes_sent, 0);
}

#[test]
fn test_netstats_has_activity() {
    let mut s = NetStats::new();
    assert!(!s.has_activity());
    s.tcp_established = 1;
    assert!(s.has_activity());
}

// The tests below guard the kernel<->userspace ABI: eBPF writes these structs
// directly into ring buffer slots (or, for NetStats, they're derived from
// SocketStatsEvent deltas folded together on the userspace side), and userspace
// reinterprets the raw bytes via an unaligned pointer read (read_ring_item in
// helpers.rs). A field added, removed, resized, or reordered on either side without
// rebuilding both halves together would silently misread every event rather than
// failing loudly - these pin the expected layout so such a change breaks a test
// instead of production.

#[test]
fn test_execve_event_layout() {
    let expected_size = size_of::<u64>() // timestamp
        + (ARG_SIZE * ARG_COUNT) // argv
        + (ENV_SIZE * ENV_COUNT) // envp
        + size_of::<u32>() * 4 // pid, gid, uid, tgid
        + 16 // command
        + LEN_MAX_PATH; // filename
    assert_eq!(size_of::<ExecveEvent>(), expected_size);
}

#[test]
fn test_readline_layout() {
    let expected_size = size_of::<u64>() // timestamp
        + size_of::<u32>() * 4 // uid, gid, pid, tgid
        + 16 // command
        + ARG_SIZE; // entry
    assert_eq!(size_of::<Readline>(), expected_size);
}

#[test]
fn test_socket_stats_event_layout() {
    // Not a plain field-size sum: udp_sockets_set (u8) sits between i32 deltas and
    // u64 deltas, so #[repr(C)] inserts 7 bytes of padding after it to satisfy the
    // u64 fields' 8-byte alignment. If this ever fails after a genuine field change,
    // recompute by hand (or print size_of/align_of) rather than just updating the
    // number to match, since silently accepting a new padding layout defeats the
    // point of this guard.
    assert_eq!(size_of::<SocketStatsEvent>(), 64);
}

#[test]
fn test_netstats_layout() {
    let expected_size = size_of::<u32>() * 6 // tcp_established/syn_recv/close_wait/time_wait/fin_wait, udp_sockets
        + size_of::<u64>() * 4; // bytes_sent, bytes_recv, packets_sent, packets_recv
    assert_eq!(size_of::<NetStats>(), expected_size);
}

#[test]
fn test_filename_offset_matches_sys_enter_execve_layout() {
    // main.rs's execve probe used to re-read the filename pointer at this raw offset;
    // it now reuses SysEnterExecve::command directly (the same pointer) instead, but
    // FILENAME_OFFSET is still part of the public API and documents that relationship.
    // If SysEnterExecve's fields are ever reordered/resized, this constant would
    // silently point at the wrong field.
    assert_eq!(
        offset_of!(SysEnterExecve, command),
        FILENAME_OFFSET,
        "FILENAME_OFFSET must match SysEnterExecve::command's actual offset"
    );
}
