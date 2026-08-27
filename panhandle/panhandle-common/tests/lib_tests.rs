//! Tests for panhandle-common library

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
