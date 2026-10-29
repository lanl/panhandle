//! Tests for eBPF ring buffer consumer functions (consume_execve_events, consume_shell_ebpf_map)

use panhandle_common::{
    ARG_COUNT, ARG_SIZE, ENV_COUNT, ENV_SIZE, ExecveEvent, LEN_MAX_PATH, Readline, SocketStatsEvent,
};
use reqwest::Client;
use std::sync::Arc;
use tokio::net::UdpSocket;

mod common {
    pub use panhandle::helpers::{
        calc_delta, event_matches_executable_filter, output_message, output_needs, read_ring_item,
        send_http_post, send_syslog,
    };
    pub use panhandle::output::OutputConfig;
    pub use panhandle_common::NetStats as MonitorNetStats;
}

#[test]
fn test_read_ring_item_roundtrip() {
    #[repr(C)]
    #[derive(Copy, Clone, PartialEq, Debug)]
    struct TestEvent {
        a: u32,
        b: u64,
        c: [u8; 4],
    }

    let original = TestEvent {
        a: 42,
        b: 123_456_789,
        c: [1, 2, 3, 4],
    };
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &original as *const TestEvent as *const u8,
            core::mem::size_of::<TestEvent>(),
        )
    };

    let reconstructed: TestEvent = unsafe { common::read_ring_item(bytes) };
    assert_eq!(original, reconstructed);
}

#[test]
fn test_read_ring_item_ignores_trailing_bytes() {
    #[repr(C)]
    #[derive(Copy, Clone, PartialEq, Debug)]
    struct TestEvent {
        a: u32,
    }

    let original = TestEvent { a: 7 };
    let mut bytes: Vec<u8> = unsafe {
        core::slice::from_raw_parts(
            &original as *const TestEvent as *const u8,
            core::mem::size_of::<TestEvent>(),
        )
    }
    .to_vec();
    bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);

    let reconstructed: TestEvent = unsafe { common::read_ring_item(&bytes) };
    assert_eq!(original, reconstructed);
}

#[test]
fn test_read_ring_item_execve_event() {
    let mut event = ExecveEvent {
        timestamp: 1_700_000_000_000_000_000,
        argv: [[0u8; ARG_SIZE]; ARG_COUNT],
        envp: [[0u8; ENV_SIZE]; ENV_COUNT],
        pid: 42,
        gid: 100,
        uid: 1000,
        tgid: 42,
        command: [0u8; 16],
        filename: [0u8; LEN_MAX_PATH],
    };
    event.argv[0][..2].copy_from_slice(b"ls");
    event.argv[1][..3].copy_from_slice(b"-la");
    event.filename[..7].copy_from_slice(b"/bin/ls");
    event.command[..2].copy_from_slice(b"ls");

    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &event as *const ExecveEvent as *const u8,
            core::mem::size_of::<ExecveEvent>(),
        )
    };

    let reconstructed: ExecveEvent = unsafe { common::read_ring_item(bytes) };
    assert_eq!(event.timestamp, reconstructed.timestamp);
    assert_eq!(event.pid, reconstructed.pid);
    assert_eq!(event.uid, reconstructed.uid);
    assert_eq!(event.gid, reconstructed.gid);
    assert_eq!(event.tgid, reconstructed.tgid);
    assert_eq!(&event.argv[0][..2], &reconstructed.argv[0][..2]);
    assert_eq!(&event.filename[..7], &reconstructed.filename[..7]);
}

#[test]
fn test_read_ring_item_readline_event() {
    let mut event = Readline {
        timestamp: 1_700_000_000_000_000_000,
        uid: 1000,
        gid: 100,
        pid: 42,
        tgid: 42,
        command: [0u8; 16],
        entry: [0u8; ARG_SIZE],
    };
    event.command[..4].copy_from_slice(b"bash");
    event.entry[..6].copy_from_slice(b"ls -la");

    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &event as *const Readline as *const u8,
            core::mem::size_of::<Readline>(),
        )
    };

    let reconstructed: Readline = unsafe { common::read_ring_item(bytes) };
    assert_eq!(event.timestamp, reconstructed.timestamp);
    assert_eq!(event.uid, reconstructed.uid);
    assert_eq!(event.pid, reconstructed.pid);
    assert_eq!(&event.command[..4], &reconstructed.command[..4]);
    assert_eq!(&event.entry[..8], &reconstructed.entry[..8]);
}

#[test]
fn test_read_ring_item_socket_stats_event() {
    let mut event = SocketStatsEvent::new(100);
    event.tcp_established_delta = 1;
    event.bytes_sent_delta = 1000;
    event.packets_sent_delta = 1;

    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &event as *const SocketStatsEvent as *const u8,
            core::mem::size_of::<SocketStatsEvent>(),
        )
    };

    let reconstructed: SocketStatsEvent = unsafe { common::read_ring_item(bytes) };
    assert_eq!(event.pid, reconstructed.pid);
    assert_eq!(
        event.tcp_established_delta,
        reconstructed.tcp_established_delta
    );
    assert_eq!(event.bytes_sent_delta, reconstructed.bytes_sent_delta);
    assert_eq!(event.packets_sent_delta, reconstructed.packets_sent_delta);
}

#[test]
fn test_executable_filter_in_consume_execve() {
    let filter = vec!["/usr/bin/ssh".to_string()];
    let batch = ["/usr/bin/ls", "/usr/bin/ssh", "/usr/bin/ssh"];

    let mut reported = Vec::new();
    for event in batch {
        if !common::event_matches_executable_filter(&filter, event) {
            continue;
        }
        reported.push(event);
    }

    assert_eq!(reported, vec!["/usr/bin/ssh", "/usr/bin/ssh"]);
}

#[test]
fn test_executable_filter_empty_matches_all() {
    let filter: Vec<String> = vec![];
    assert!(common::event_matches_executable_filter(
        &filter,
        "/usr/bin/ssh"
    ));
    assert!(common::event_matches_executable_filter(
        &filter,
        "/usr/bin/ls"
    ));
    assert!(common::event_matches_executable_filter(&filter, ""));
}

#[test]
fn test_executable_filter_exact_match() {
    let filter = vec!["/usr/bin/ssh".to_string()];
    assert!(common::event_matches_executable_filter(
        &filter,
        "/usr/bin/ssh"
    ));
    assert!(!common::event_matches_executable_filter(
        &filter,
        "/usr/bin/ssh-copy-id"
    ));
    assert!(!common::event_matches_executable_filter(&filter, "ssh"));
    assert!(!common::event_matches_executable_filter(
        &filter, "/usr/bin"
    ));
}

#[tokio::test]
async fn test_output_message_no_channels() {
    let client = Client::new();
    let hostname = Arc::new("node1".to_string());
    let syslog_address = Arc::new(String::new());
    let global_url = Arc::new(String::new());
    let plain = "plain text".to_string();
    let json = "{\"a\":1}".to_string();

    common::output_message(
        &false,
        &false,
        &hostname,
        &syslog_address,
        &global_url,
        &true,
        &plain,
        &json,
        &client,
        &false,
    )
    .await;

    common::output_message(
        &false,
        &false,
        &hostname,
        &syslog_address,
        &global_url,
        &false,
        &plain,
        &json,
        &client,
        &true,
    )
    .await;
}

#[tokio::test]
async fn test_send_http_post_invalid_url() {
    let client = Client::new();
    let url = Arc::new("not a url".to_string());
    let body = Arc::new("payload".to_string());

    let result = common::send_http_post(&client, &url, &body, &false, &false).await;
    assert!(result.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_send_syslog_udp_loopback() {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind loopback UDP socket");
    let port = socket.local_addr().expect("local addr").port();
    let syslog_address = Arc::new(format!("127.0.0.1:{}/udp", port));
    let message = Arc::new("panhandle udp test message".to_string());
    let hostname = "testhost".to_string();

    let result = common::send_syslog(&hostname, &message, &syslog_address, &false, &false).await;
    assert!(result.is_ok());

    let mut buf = [0u8; 2048];
    let (len, _src) = socket
        .recv_from(&mut buf)
        .await
        .expect("receive syslog datagram");
    let received = String::from_utf8_lossy(&buf[..len]);
    assert!(
        received.contains("panhandle udp test message"),
        "syslog datagram should carry the message, got: {received}"
    );
}

#[test]
fn test_output_needs_logic() {
    // no output channels, no debug: only the plain terminal log is used
    assert_eq!(
        common::output_needs(false, false, false, false),
        (true, false)
    );
    // no output channels, debug on: the terminal log always uses the json form when debug
    assert_eq!(
        common::output_needs(false, false, false, true),
        (false, true)
    );
    // http on, non-json: http uses plain, terminal (non-debug) uses plain
    assert_eq!(
        common::output_needs(true, false, false, false),
        (true, false)
    );
    // http on, json requested: http and the terminal (non-debug) both use json
    assert_eq!(
        common::output_needs(true, false, true, false),
        (false, true)
    );
    // http on, json requested, debug on: plain is unused by either channel now
    assert_eq!(common::output_needs(true, false, true, true), (false, true));
    // syslog behaves the same as http for channel selection
    assert_eq!(
        common::output_needs(false, true, false, false),
        (true, false)
    );
    // json_output with no channel enabled: the terminal (non-debug) now needs json
    assert_eq!(
        common::output_needs(false, false, true, false),
        (false, true)
    );
    // json_output with no channel enabled but debug on: only the debug terminal path needs json
    assert_eq!(
        common::output_needs(false, false, true, true),
        (false, true)
    );
}

#[test]
fn test_calc_delta_for_consumer() {
    // no prior observation: must not compute a delta against an implicit 0 baseline
    assert_eq!(common::calc_delta(1_000_000_000, None), 0);
    assert_eq!(common::calc_delta(0, None), 0);
    // normal case: delta against a real prior observation
    assert_eq!(common::calc_delta(100, Some(40)), 60);
    // no change since last observation
    assert_eq!(common::calc_delta(50, Some(50)), 0);
    // counter went backwards (e.g. PID reuse observed a lower value): saturates to 0
    assert_eq!(common::calc_delta(100, Some(150)), 0);
}

#[test]
fn test_consume_execve_event_filtering() {
    // Simulate the filtering logic from consume_execve_events
    let executable_vec = vec!["/usr/bin/ssh".to_string(), "/usr/bin/scp".to_string()];

    let mut test_events = Vec::new();

    // Event 1: matches filter
    let mut event1 = ExecveEvent {
        timestamp: 1_700_000_000_000_000_000,
        argv: [[0u8; ARG_SIZE]; ARG_COUNT],
        envp: [[0u8; ENV_SIZE]; ENV_COUNT],
        pid: 42,
        gid: 100,
        uid: 1000,
        tgid: 42,
        command: [0u8; 16],
        filename: [0u8; LEN_MAX_PATH],
    };
    let ssh_path = b"/usr/bin/ssh";
    event1.filename[..ssh_path.len()].copy_from_slice(ssh_path);
    test_events.push(event1);

    // Event 2: doesn't match filter
    let mut event2 = ExecveEvent {
        timestamp: 1_700_000_000_000_000_001,
        argv: [[0u8; ARG_SIZE]; ARG_COUNT],
        envp: [[0u8; ENV_SIZE]; ENV_COUNT],
        pid: 43,
        gid: 100,
        uid: 1000,
        tgid: 43,
        command: [0u8; 16],
        filename: [0u8; LEN_MAX_PATH],
    };
    event2.filename[..7].copy_from_slice(b"/bin/ls");
    test_events.push(event2);

    // Event 3: matches filter
    let mut event3 = ExecveEvent {
        timestamp: 1_700_000_000_000_000_002,
        argv: [[0u8; ARG_SIZE]; ARG_COUNT],
        envp: [[0u8; ENV_SIZE]; ENV_COUNT],
        pid: 44,
        gid: 100,
        uid: 1000,
        tgid: 44,
        command: [0u8; 16],
        filename: [0u8; LEN_MAX_PATH],
    };
    let scp_path = b"/usr/bin/scp";
    event3.filename[..scp_path.len()].copy_from_slice(scp_path);
    test_events.push(event3);

    let mut matched = Vec::new();
    for event in &test_events {
        let filename = std::str::from_utf8(&event.filename)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .trim();
        if common::event_matches_executable_filter(&executable_vec, filename) {
            matched.push(event.pid);
        }
    }

    assert_eq!(matched, vec![42, 44]);
}

#[test]
fn test_consume_shell_event_filtering() {
    // Similar filtering for shell events (readline/zlentry)
    let executable_vec = vec!["bash".to_string(), "zsh".to_string()];

    let mut test_events = Vec::new();

    // Event 1: matches filter (bash)
    let mut event1 = Readline {
        timestamp: 1_700_000_000_000_000_000,
        uid: 1000,
        gid: 100,
        pid: 42,
        tgid: 42,
        command: [0u8; 16],
        entry: [0u8; ARG_SIZE],
    };
    event1.command[..4].copy_from_slice(b"bash");
    test_events.push(event1);

    // Event 2: doesn't match filter (python)
    let mut event2 = Readline {
        timestamp: 1_700_000_000_000_000_001,
        uid: 1000,
        gid: 100,
        pid: 43,
        tgid: 43,
        command: [0u8; 16],
        entry: [0u8; ARG_SIZE],
    };
    event2.command[..6].copy_from_slice(b"python");
    test_events.push(event2);

    // Event 3: matches filter (zsh)
    let mut event3 = Readline {
        timestamp: 1_700_000_000_000_000_002,
        uid: 1000,
        gid: 100,
        pid: 44,
        tgid: 44,
        command: [0u8; 16],
        entry: [0u8; ARG_SIZE],
    };
    event3.command[..3].copy_from_slice(b"zsh");
    test_events.push(event3);

    let mut matched = Vec::new();
    for event in &test_events {
        let command = std::str::from_utf8(&event.command)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .trim();
        if common::event_matches_executable_filter(&executable_vec, command) {
            matched.push(event.pid);
        }
    }

    assert_eq!(matched, vec![42, 44]);
}

#[test]
fn test_socket_stats_event_accumulation() {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    let net_stats: Arc<Mutex<HashMap<u32, common::MonitorNetStats>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // First event for pid 100
    let mut e1 = SocketStatsEvent::new(100);
    e1.tcp_established_delta = 1;
    e1.bytes_sent_delta = 1000;
    e1.packets_sent_delta = 1;
    apply_socket_stats_event(&net_stats, &e1);

    // Second event, same pid
    let mut e2 = SocketStatsEvent::new(100);
    e2.tcp_established_delta = 1;
    e2.bytes_sent_delta = 500;
    e2.bytes_recv_delta = 2000;
    e2.packets_recv_delta = 3;
    e2.udp_sockets_set = 1;
    apply_socket_stats_event(&net_stats, &e2);

    {
        let map = net_stats.lock().unwrap();
        let stats = &map[&100];
        assert_eq!(stats.tcp_established, 2);
        assert_eq!(stats.bytes_sent, 1500);
        assert_eq!(stats.bytes_recv, 2000);
        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.packets_recv, 3);
        assert_eq!(stats.udp_sockets, 1);
    }

    // Decrement saturates at 0
    let mut e3 = SocketStatsEvent::new(100);
    e3.tcp_established_delta = -5;
    apply_socket_stats_event(&net_stats, &e3);
    assert_eq!(net_stats.lock().unwrap()[&100].tcp_established, 0);

    // udp_sockets_set is sticky
    let e4 = SocketStatsEvent::new(100);
    apply_socket_stats_event(&net_stats, &e4);
    assert_eq!(net_stats.lock().unwrap()[&100].udp_sockets, 1);

    // Different pid gets independent entry
    let mut e5 = SocketStatsEvent::new(200);
    e5.bytes_sent_delta = 42;
    apply_socket_stats_event(&net_stats, &e5);
    let map = net_stats.lock().unwrap();
    assert_eq!(map[&200].bytes_sent, 42);
    assert_eq!(map.len(), 2);
}

fn apply_socket_stats_event(
    net_stats: &Arc<std::sync::Mutex<std::collections::HashMap<u32, common::MonitorNetStats>>>,
    event: &SocketStatsEvent,
) {
    let mut map = net_stats.lock().unwrap();
    let entry = map.entry(event.pid).or_default();
    entry.tcp_established = entry
        .tcp_established
        .saturating_add_signed(event.tcp_established_delta);
    entry.tcp_syn_recv = entry
        .tcp_syn_recv
        .saturating_add_signed(event.tcp_syn_recv_delta);
    entry.tcp_close_wait = entry
        .tcp_close_wait
        .saturating_add_signed(event.tcp_close_wait_delta);
    entry.tcp_time_wait = entry
        .tcp_time_wait
        .saturating_add_signed(event.tcp_time_wait_delta);
    entry.tcp_fin_wait = entry
        .tcp_fin_wait
        .saturating_add_signed(event.tcp_fin_wait_delta);
    if event.udp_sockets_set != 0 {
        entry.udp_sockets = entry.udp_sockets.max(1);
    }
    entry.bytes_sent += event.bytes_sent_delta;
    entry.bytes_recv += event.bytes_recv_delta;
    entry.packets_sent += event.packets_sent_delta;
    entry.packets_recv += event.packets_recv_delta;
}

#[test]
fn test_output_config_creation_for_consumers() {
    let hostname = Arc::new("test-host".to_string());
    let client = Client::new();

    let output = common::OutputConfig::new(
        hostname.clone(),
        true,  // json
        false, // http
        false, // syslog
        Arc::new("unix".to_string()),
        Arc::new("http://localhost:8080".to_string()),
        false, // debug
        client,
    )
    .expect("OutputConfig::new should succeed");

    assert!(output.json);
    assert!(!output.http);
    assert!(!output.syslog);
    assert_eq!(output.hostname.as_str(), "test-host");
}

#[test]
fn test_format_execve_event_for_consumer() {
    let hostname = Arc::new("test-host".to_string());
    let client = Client::new();

    let output = common::OutputConfig::new(
        hostname.clone(),
        true,  // json
        false, // http
        false, // syslog
        Arc::new("unix".to_string()),
        Arc::new("http://localhost:8080".to_string()),
        false, // debug
        client,
    )
    .expect("OutputConfig::new should succeed");

    let mut event = ExecveEvent {
        timestamp: 1_700_000_000_000_000_000,
        argv: [[0u8; ARG_SIZE]; ARG_COUNT],
        envp: [[0u8; ENV_SIZE]; ENV_COUNT],
        pid: 42,
        gid: 100,
        uid: 1000,
        tgid: 42,
        command: [0u8; 16],
        filename: [0u8; LEN_MAX_PATH],
    };
    event.argv[0][..2].copy_from_slice(b"ls");
    event.argv[1][..3].copy_from_slice(b"-la");
    event.filename[..7].copy_from_slice(b"/bin/ls");
    event.command[..2].copy_from_slice(b"ls");

    let json_payload = output.format_execve_event_json(&event, "execve");
    let text_payload = output.format_execve_event_text(&event, "execve");

    let parsed: serde_json::Value = serde_json::from_str(&json_payload).expect("Valid JSON");
    assert_eq!(parsed["type"], "execve");
    assert_eq!(parsed["filename"], "/bin/ls");
    assert_eq!(parsed["command"], "ls");
    assert_eq!(parsed["args"], serde_json::json!(["ls", "-la"]));
    assert_eq!(parsed["uid"], 1000);

    assert!(text_payload.contains("execve"));
    assert!(text_payload.contains("/bin/ls"));
    assert!(text_payload.contains(r#"["ls", "-la"]"#));
    assert!(text_payload.contains("1000"));
}

#[test]
fn test_format_shell_event_for_consumer() {
    let hostname = Arc::new("test-host".to_string());
    let client = Client::new();

    let output = common::OutputConfig::new(
        hostname.clone(),
        true,  // json
        false, // http
        false, // syslog
        Arc::new("unix".to_string()),
        Arc::new("http://localhost:8080".to_string()),
        false, // debug
        client,
    )
    .expect("OutputConfig::new should succeed");

    let mut event = Readline {
        timestamp: 1_700_000_000_000_000_000,
        uid: 1000,
        gid: 100,
        pid: 42,
        tgid: 42,
        command: [0u8; 16],
        entry: [0u8; ARG_SIZE],
    };
    event.command[..4].copy_from_slice(b"bash");
    event.entry[..6].copy_from_slice(b"ls -la");

    let json_payload = output.format_shell_event_json(&event, "readline");
    let text_payload = output.format_shell_event_text(&event, "readline");

    let parsed: serde_json::Value = serde_json::from_str(&json_payload).expect("Valid JSON");
    assert_eq!(parsed["type"], "shell");
    assert_eq!(parsed["shell_type"], "readline");
    assert_eq!(parsed["command"], "bash");
    assert_eq!(parsed["entry"], "ls -la");
    assert_eq!(parsed["uid"], 1000);

    assert!(text_payload.contains("readline"));
    assert!(text_payload.contains("bash"));
    assert!(text_payload.contains("ls -la"));
    assert!(text_payload.contains("1000"));
}
