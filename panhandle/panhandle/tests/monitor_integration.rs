//! Integration tests for monitor functions (CPU, GPU, IO, Network)

use std::collections::{HashMap, HashSet};

mod common {
    pub use panhandle::helpers::{
        calc_delta, event_matches_executable_filter, format_owner, format_state,
        format_state_prose, get_canonical_executable_list, get_process_uid, json_quoted,
        output_needs, resolve_comm_list_mode, resolve_username, validate_count, validate_syslog,
        validate_url,
    };
    pub use panhandle::monitor_cpu_usage::{
        PidStats, build_found_entry, calc_cpu_percent, calc_system_cpu_percent, evict_stale_pids,
        format_cpu_json, format_cpu_not_found_json, format_cpu_not_found_prose, format_cpu_prose,
        format_system_cpu_json, format_system_cpu_prose,
    };
    pub use panhandle::monitor_gpu_usage::{
        format_gpu_process_json, format_gpu_prose, format_gpu_summary_json,
        format_gpu_summary_prose,
    };
    pub use panhandle::monitor_io_usage::{format_io_json, format_io_prose};
    pub use panhandle::monitor_network_usage::{
        SharedNetStats, apply_socket_stats_event, format_socket_json, format_socket_prose,
        get_network_info, ip_to_interface, prune_dead_pids,
    };
    pub use panhandle::procfs_helpers::{
        format_faults_json, format_faults_prose, format_mem_json, format_mem_prose,
    };
    pub use panhandle_common::NetStats;
    pub use panhandle_common::{
        ALLOW_LIST, DENY_LIST, EXECUTABLE_COUNT, MAX_BLOCKED_COMMS, MAX_BLOCKED_PATHS, NO_LIST,
        UID_COUNT,
    };
}

#[test]
fn test_cpu_monitor_format_functions() {
    // Test format_cpu_prose verbose
    let verbose = common::format_cpu_prose(
        true,
        42,
        "bash",
        Some(1),
        Some("systemd"),
        Some(0),
        Some("root"),
        Some('S'),
        1234.5,
        56.25,
        12.5,
        7.25,
        90.0,
    );
    assert!(verbose.contains("Type: cpu"));
    assert!(verbose.contains("PID: 42"));
    assert!(verbose.contains("Comm: bash"));
    assert!(verbose.contains("Parent PID: 1"));
    assert!(verbose.contains("Parent Comm: systemd"));
    assert!(verbose.contains("User ID: 0"));
    assert!(verbose.contains("User: root"));
    assert!(verbose.contains("State: sleeping"));
    assert!(verbose.contains("Total Time: 1234.50 ms"));
    assert!(verbose.contains("Delta Time: 56.25 ms"));
    assert!(verbose.contains("CPU: 12.50%"));
    assert!(verbose.contains("Avg CPU: 7.25%"));
    assert!(verbose.contains("Max CPU: 90.00%"));

    // Test format_cpu_prose compact
    let compact = common::format_cpu_prose(
        false, 42, "bash", None, None, None, None, None, 0.0, 0.0, 12.5, 7.25, 90.0,
    );
    assert!(compact.contains("Type: cpu"));
    assert!(compact.contains("PID: 42"));
    assert!(compact.contains("Comm: bash"));
    assert!(compact.contains("CPU: 12.50%"));
    assert!(compact.contains("Avg CPU: 7.25%"));
    assert!(compact.contains("Max CPU: 90.00%"));
    assert!(!compact.contains("Parent PID"));

    // Test format_cpu_not_found_prose verbose
    let not_found_verbose = common::format_cpu_not_found_prose(
        true,
        42,
        "bash",
        Some(1),
        Some("systemd"),
        Some(0),
        Some("root"),
    );
    assert!(not_found_verbose.contains("Status: not_found"));
    assert!(not_found_verbose.contains("Parent PID: 1"));

    // Test format_cpu_not_found_prose compact
    let not_found_compact =
        common::format_cpu_not_found_prose(false, 42, "bash", None, None, None, None);
    assert_eq!(
        not_found_compact,
        "Type: cpu, PID: 42, Comm: bash, Status: not_found"
    );

    // Test format_system_cpu_prose
    let system = common::format_system_cpu_prose(25.0, 4, 1000.0);
    assert_eq!(
        system,
        "Type: cpu, CPU: 25.00%, CPUs: 4, Busy Delta: 1000.00 ms"
    );
}

#[test]
fn test_cpu_monitor_json_functions() {
    let hostile = "ba\"sh\\\u{1b}[31m";

    // Test format_cpu_json verbose
    let verbose = common::format_cpu_json(
        true,
        42,
        hostile,
        Some(1),
        Some("systemd"),
        Some(0),
        Some("root"),
        Some('S'),
        1234.5,
        56.25,
        12.5,
        7.25,
        90.0,
    );
    let parsed: serde_json::Value = serde_json::from_str(&verbose).expect("Valid JSON");
    assert_eq!(parsed["Type"], "cpu");
    assert_eq!(parsed["PID"], 42);
    assert_eq!(parsed["Comm"], hostile);
    assert_eq!(parsed["PPID"], 1);
    assert_eq!(parsed["Parent_Comm"], "systemd");
    assert_eq!(parsed["UID"], "0");
    assert_eq!(parsed["Username"], "root");
    assert_eq!(parsed["State"], "S");
    assert_eq!(parsed["Total_Time_ms"], 1234.5);
    assert_eq!(parsed["Delta_Time_ms"], 56.25);
    assert_eq!(parsed["CPU%"], 12.5);
    assert_eq!(parsed["Avg_CPU%"], 7.25);
    assert_eq!(parsed["Max_CPU%"], 90.0);

    // Test format_cpu_json compact
    let compact = common::format_cpu_json(
        false, 42, hostile, None, None, None, None, None, 0.0, 0.0, 12.5, 7.25, 90.0,
    );
    let parsed: serde_json::Value = serde_json::from_str(&compact).expect("Valid JSON");
    assert_eq!(parsed["Type"], "cpu");
    assert_eq!(parsed["PID"], 42);
    assert_eq!(parsed["Comm"], hostile);
    assert_eq!(parsed["CPU%"], 12.5);
    assert!(!parsed.as_object().unwrap().contains_key("PPID"));

    // Test format_cpu_not_found_json
    let not_found = common::format_cpu_not_found_json(
        true,
        42,
        hostile,
        Some(1),
        Some("systemd"),
        Some(0),
        Some("root"),
    );
    let parsed: serde_json::Value = serde_json::from_str(&not_found).expect("Valid JSON");
    assert_eq!(parsed["Status"], "not_found");

    // Test format_system_cpu_json
    let system = common::format_system_cpu_json(42.5, 8, 1234.5);
    let parsed: serde_json::Value = serde_json::from_str(&system).expect("Valid JSON");
    assert_eq!(parsed["Type"], "cpu");
    assert_eq!(parsed["CPU%"], 42.5);
    assert_eq!(parsed["Num_CPUs"], 8);
    assert_eq!(parsed["Busy_Delta_ms"], 1234.5);
}

#[test]
fn test_cpu_calc_functions() {
    // calc_cpu_percent
    assert_eq!(
        common::calc_cpu_percent(1_000_000_000, 1_000_000_000),
        100.0
    );
    assert_eq!(common::calc_cpu_percent(500_000_000, 1_000_000_000), 50.0);
    assert_eq!(common::calc_cpu_percent(0, 1_000_000_000), 0.0);
    assert_eq!(
        common::calc_cpu_percent(2_000_000_000, 1_000_000_000),
        200.0
    );
    assert_eq!(common::calc_cpu_percent(1_000_000_000, 0), 0.0);

    // calc_system_cpu_percent
    assert_eq!(
        common::calc_system_cpu_percent(1_000_000_000, 1_000_000_000, 4),
        25.0
    );
    assert_eq!(
        common::calc_system_cpu_percent(4_000_000_000, 1_000_000_000, 4),
        100.0
    );
    assert_eq!(common::calc_system_cpu_percent(0, 1_000_000_000, 4), 0.0);
    assert_eq!(
        common::calc_system_cpu_percent(5_000_000_000, 1_000_000_000, 4),
        100.0
    );
    assert_eq!(common::calc_system_cpu_percent(1_000_000_000, 0, 4), 0.0);
    assert_eq!(
        common::calc_system_cpu_percent(1_000_000_000, 1_000_000_000, 0),
        0.0
    );
}

#[test]
fn test_cpu_evict_stale_pids() {
    let mut last_pid_times: HashMap<u32, u64> = HashMap::from([(1, 100), (2, 200), (3, 300)]);
    let mut pid_stats: HashMap<u32, common::PidStats> = HashMap::from([
        (1, common::PidStats::default()),
        (2, common::PidStats::default()),
    ]);

    let live_pids: HashSet<u32> = HashSet::from([1, 2]);
    common::evict_stale_pids(&mut last_pid_times, &mut pid_stats, &live_pids);

    assert_eq!(
        last_pid_times.keys().copied().collect::<HashSet<_>>(),
        HashSet::from([1, 2])
    );
    assert_eq!(
        pid_stats.keys().copied().collect::<HashSet<_>>(),
        HashSet::from([1, 2])
    );

    // Empty live set drops everything
    common::evict_stale_pids(&mut last_pid_times, &mut pid_stats, &HashSet::new());
    assert!(last_pid_times.is_empty());
    assert!(pid_stats.is_empty());
}

#[test]
fn test_cpu_build_found_entry() {
    use procfs::process::Process;
    use std::collections::HashMap;

    let pid = std::process::id();
    let stat = Process::new(pid as i32)
        .and_then(|p| p.stat())
        .expect("stat should succeed");
    let ticks_per_second = procfs::ticks_per_second();
    let expected_cpu_time = (stat.utime + stat.stime) * 1_000_000_000 / ticks_per_second;
    let interval_ns = 1_000_000_000u64;

    let mut last_pid_times: HashMap<u32, u64> = HashMap::new();
    last_pid_times.insert(pid, 0);
    let mut pid_stats = HashMap::new();

    let e1 = common::build_found_entry(
        pid,
        stat.clone(),
        None,
        None,
        ticks_per_second,
        interval_ns,
        &mut last_pid_times,
        &mut pid_stats,
    );
    assert_eq!(e1.cpu_time, expected_cpu_time);
    assert_eq!(e1.delta, expected_cpu_time);
    let expected_percent1 = common::calc_cpu_percent(expected_cpu_time, interval_ns);
    assert_eq!(e1.cpu_percent, expected_percent1);
    assert_eq!(e1.avg_cpu_percent, expected_percent1);
    assert_eq!(e1.max_cpu_percent, expected_percent1);
    assert_eq!(last_pid_times[&pid], expected_cpu_time);

    // Second sample with same stat -> zero elapsed cpu time
    let e2 = common::build_found_entry(
        pid,
        stat.clone(),
        None,
        None,
        ticks_per_second,
        interval_ns,
        &mut last_pid_times,
        &mut pid_stats,
    );
    assert_eq!(e2.delta, 0);
    assert_eq!(e2.cpu_percent, 0.0);
    assert_eq!(e2.avg_cpu_percent, expected_percent1 / 2.0);
    assert_eq!(e2.max_cpu_percent, expected_percent1);
}

#[test]
fn test_gpu_monitor_format_functions() {
    // Test format_gpu_prose verbose
    let verbose = common::format_gpu_prose(
        true,
        42,
        "nvidia-smi",
        Some(1),
        Some("systemd"),
        Some(0),
        Some("root"),
        0,
        25,
        10,
        5,
    );
    assert!(verbose.contains("Type: gpu"));
    assert!(verbose.contains("PID: 42"));
    assert!(verbose.contains("Comm: nvidia-smi"));
    assert!(verbose.contains("Parent PID: 1"));
    assert!(verbose.contains("Parent Comm: systemd"));
    assert!(verbose.contains("User ID: 0"));
    assert!(verbose.contains("User: root"));
    assert!(verbose.contains("GPU: 0"));
    assert!(verbose.contains("VRAM: 25%"));
    assert!(verbose.contains("Encoder: 10%"));
    assert!(verbose.contains("Decoder: 5%"));

    // Test format_gpu_prose compact
    let compact = common::format_gpu_prose(
        false,
        42,
        "nvidia-smi",
        None,
        None,
        None,
        None,
        0,
        25,
        10,
        5,
    );
    assert!(compact.contains("Type: gpu"));
    assert!(compact.contains("PID: 42"));
    assert!(compact.contains("Comm: nvidia-smi"));
    assert!(compact.contains("GPU: 0"));
    assert!(compact.contains("VRAM: 25%"));
    assert!(!compact.contains("Parent PID"));

    // Test format_gpu_summary_prose
    let summary = common::format_gpu_summary_prose("0", 90, 80, 4096, 30, 20, 65);
    assert_eq!(
        summary,
        "Type: gpu, GPU: 0, Utilization: 90%, VRAM: 80%, VRAM Used: 4096 MB, Encoder: 30%, Decoder: 20%, Temperature: 65°C"
    );
}

#[test]
fn test_gpu_monitor_json_functions() {
    let hostile = "nvidia-smi\"\\\u{1b}";

    // Test format_gpu_process_json verbose
    let verbose = common::format_gpu_process_json(
        true,
        42,
        hostile,
        Some(1),
        Some("systemd"),
        Some(0),
        Some("root"),
        0,
        25,
        10,
        5,
    );
    let parsed: serde_json::Value = serde_json::from_str(&verbose).expect("Valid JSON");
    assert_eq!(parsed["Type"], "gpu");
    assert_eq!(parsed["PID"], 42);
    assert_eq!(parsed["Comm"], hostile);
    assert_eq!(parsed["PPID"], 1);
    assert_eq!(parsed["Parent_Comm"], "systemd");
    assert_eq!(parsed["UID"], "0");
    assert_eq!(parsed["Username"], "root");
    assert_eq!(parsed["GPU_ID"], 0);
    assert_eq!(parsed["VRAM_Percent"], 25);
    assert_eq!(parsed["Encoder_Percent"], 10);
    assert_eq!(parsed["Decoder_Percent"], 5);

    // Test format_gpu_process_json compact
    let compact =
        common::format_gpu_process_json(false, 42, hostile, None, None, None, None, 0, 25, 10, 5);
    let parsed: serde_json::Value = serde_json::from_str(&compact).expect("Valid JSON");
    assert_eq!(parsed["Type"], "gpu");
    assert_eq!(parsed["PID"], 42);
    assert_eq!(parsed["Comm"], hostile);
    assert_eq!(parsed["GPU_ID"], 0);
    assert!(!parsed.as_object().unwrap().contains_key("PPID"));

    // Test format_gpu_summary_json with UUID
    let uuid = "GPU-6e6f2c5a-6c1e-8b3a-4a2f-0d2c1b4a9e8f";
    let summary = common::format_gpu_summary_json(uuid, 90, 80, 4096, 30, 20, 65);
    let parsed: serde_json::Value = serde_json::from_str(&summary).expect("Valid JSON");
    assert_eq!(parsed["Type"], "gpu");
    assert_eq!(parsed["GPU_ID"], uuid);
    assert_eq!(parsed["GPU_Percent"], 90);
    assert_eq!(parsed["VRAM_Percent"], 80);
    assert_eq!(parsed["VRAM_MB"], 4096);
    assert_eq!(parsed["Encoder_Percent"], 30);
    assert_eq!(parsed["Decoder_Percent"], 20);
    assert_eq!(parsed["Temperature_C"], 65);
}

#[test]
fn test_io_monitor_format_functions() {
    // Test format_io_prose verbose
    let verbose = common::format_io_prose(
        true,
        42,
        "bash",
        Some(1),
        Some("systemd"),
        Some(0),
        Some("root"),
        Some('S'),
        100,
        50,
        1024,
        512,
        12,
        10,
    );
    assert!(verbose.contains("Type: io"));
    assert!(verbose.contains("PID: 42"));
    assert!(verbose.contains("Comm: bash"));
    assert!(verbose.contains("Parent PID: 1"));
    assert!(verbose.contains("Parent Comm: systemd"));
    assert!(verbose.contains("User ID: 0"));
    assert!(verbose.contains("User: root"));
    assert!(verbose.contains("State: sleeping"));
    assert!(verbose.contains("Read Count: 100"));
    assert!(verbose.contains("Write Count: 50"));
    assert!(verbose.contains("Read: 1024 MB"));
    assert!(verbose.contains("Write: 512 MB"));
    assert!(verbose.contains("Open FDs: 12"));
    assert!(verbose.contains("Unique Inodes: 10"));

    // Test format_io_prose compact
    let compact = common::format_io_prose(
        false, 42, "bash", None, None, None, None, None, 100, 50, 1024, 512, 12, 10,
    );
    assert!(compact.contains("Type: io"));
    assert!(compact.contains("PID: 42"));
    assert!(compact.contains("Comm: bash"));
    assert!(compact.contains("Read Count: 100"));
    assert!(compact.contains("Write Count: 50"));
    assert!(!compact.contains("Parent PID"));
}

#[test]
fn test_io_monitor_json_functions() {
    let hostile = "bash\"\\\u{1b}[31m";

    // Test format_io_json verbose
    let verbose = common::format_io_json(
        true,
        42,
        hostile,
        Some(1),
        Some("systemd"),
        Some(0),
        Some("root"),
        Some('S'),
        100,
        50,
        1024,
        512,
        12,
        10,
    );
    let parsed: serde_json::Value = serde_json::from_str(&verbose).expect("Valid JSON");
    assert_eq!(parsed["Type"], "io");
    assert_eq!(parsed["PID"], 42);
    assert_eq!(parsed["Comm"], hostile);
    assert_eq!(parsed["PPID"], 1);
    assert_eq!(parsed["Parent_Comm"], "systemd");
    assert_eq!(parsed["UID"], "0");
    assert_eq!(parsed["Username"], "root");
    assert_eq!(parsed["State"], "S");
    assert_eq!(parsed["Read_Count"], 100);
    assert_eq!(parsed["Write_Count"], 50);
    assert_eq!(parsed["Read_MB"], 1024);
    assert_eq!(parsed["Write_MB"], 512);
    assert_eq!(parsed["Open_FDs"], 12);
    assert_eq!(parsed["Unique_Inodes"], 10);

    // Test format_io_json compact
    let compact = common::format_io_json(
        false, 42, hostile, None, None, None, None, None, 100, 50, 1024, 512, 12, 10,
    );
    let parsed: serde_json::Value = serde_json::from_str(&compact).expect("Valid JSON");
    assert_eq!(parsed["Type"], "io");
    assert_eq!(parsed["PID"], 42);
    assert_eq!(parsed["Comm"], hostile);
    assert_eq!(parsed["Read_Count"], 100);
    assert!(!parsed.as_object().unwrap().contains_key("PPID"));
}

#[test]
fn test_network_monitor_format_functions() {
    let stats = common::NetStats {
        tcp_established: 5,
        tcp_syn_recv: 1,
        tcp_close_wait: 2,
        tcp_time_wait: 3,
        tcp_fin_wait: 4,
        udp_sockets: 6,
        bytes_sent: 10 * 1024 * 1024,
        bytes_recv: 20 * 1024 * 1024,
        packets_sent: 100,
        packets_recv: 200,
    };

    // Test format_socket_prose verbose
    let verbose = common::format_socket_prose(
        true,
        42,
        "sshd",
        Some(1),
        Some("systemd"),
        Some(0),
        Some("root"),
        Some('S'),
        "eth0",
        "192.168.1.10",
        "aa:bb:cc:dd:ee:ff",
        &stats,
        10,
        20,
    );
    assert!(verbose.contains("Type: sock"));
    assert!(verbose.contains("PID: 42"));
    assert!(verbose.contains("Comm: sshd"));
    assert!(verbose.contains("Parent PID: 1"));
    assert!(verbose.contains("Parent Comm: systemd"));
    assert!(verbose.contains("User ID: 0"));
    assert!(verbose.contains("User: root"));
    assert!(verbose.contains("State: sleeping"));
    assert!(verbose.contains("NIC: eth0"));
    assert!(verbose.contains("IP: 192.168.1.10"));
    assert!(verbose.contains("MAC: aa:bb:cc:dd:ee:ff"));
    assert!(verbose.contains("Established: 5"));
    assert!(verbose.contains("Syn Recv: 1"));
    assert!(verbose.contains("Close Wait: 2"));
    assert!(verbose.contains("Fin Wait: 4"));
    assert!(verbose.contains("Time Wait: 3"));
    assert!(verbose.contains("UDP: 6"));
    assert!(verbose.contains("Sent: 10 MB"));
    assert!(verbose.contains("Received: 20 MB"));
    assert!(verbose.contains("Packets Sent: 100"));
    assert!(verbose.contains("Packets Received: 200"));

    // Test format_socket_prose compact
    let compact = common::format_socket_prose(
        false,
        42,
        "sshd",
        None,
        None,
        None,
        None,
        None,
        "eth0",
        "192.168.1.10",
        "aa:bb:cc:dd:ee:ff",
        &stats,
        10,
        20,
    );
    assert!(compact.contains("Type: sock"));
    assert!(compact.contains("PID: 42"));
    assert!(compact.contains("Comm: sshd"));
    assert!(compact.contains("NIC: eth0"));
    assert!(!compact.contains("Parent PID"));
}

#[test]
fn test_network_monitor_json_functions() {
    let stats = common::NetStats {
        tcp_established: 5,
        tcp_syn_recv: 1,
        tcp_close_wait: 2,
        tcp_time_wait: 3,
        tcp_fin_wait: 4,
        udp_sockets: 6,
        bytes_sent: 10 * 1024 * 1024,
        bytes_recv: 20 * 1024 * 1024,
        packets_sent: 100,
        packets_recv: 200,
    };
    let hostile = "sshd\"\\\u{1b}[31m";

    // Test format_socket_json verbose
    let verbose = common::format_socket_json(
        true,
        42,
        hostile,
        Some(1),
        Some("systemd"),
        Some(0),
        Some("root"),
        Some('S'),
        "eth0",
        "192.168.1.10",
        "aa:bb:cc:dd:ee:ff",
        &stats,
        10,
        20,
    );
    let parsed: serde_json::Value = serde_json::from_str(&verbose).expect("Valid JSON");
    assert_eq!(parsed["Type"], "sock");
    assert_eq!(parsed["PID"], 42);
    assert_eq!(parsed["Comm"], hostile);
    assert_eq!(parsed["PPID"], 1);
    assert_eq!(parsed["Parent_Comm"], "systemd");
    assert_eq!(parsed["UID"], "0");
    assert_eq!(parsed["Username"], "root");
    assert_eq!(parsed["State"], "S");
    assert_eq!(parsed["NIC"], "eth0");
    assert_eq!(parsed["IP"], "192.168.1.10");
    assert_eq!(parsed["MAC"], "aa:bb:cc:dd:ee:ff");
    assert_eq!(parsed["ESTAB"], 5);
    assert_eq!(parsed["SYN_RECV"], 1);
    assert_eq!(parsed["CLOSE_WAIT"], 2);
    assert_eq!(parsed["FIN_WAIT"], 4);
    assert_eq!(parsed["TIME_WAIT"], 3);
    assert_eq!(parsed["UDP"], 6);
    assert_eq!(parsed["MB_Sent"], 10);
    assert_eq!(parsed["MB_Recv"], 20);
    assert_eq!(parsed["Packets_Sent"], 100);
    assert_eq!(parsed["Packets_Recv"], 200);

    // Test format_socket_json compact
    let compact = common::format_socket_json(
        false,
        42,
        hostile,
        None,
        None,
        None,
        None,
        None,
        "eth0",
        "192.168.1.10",
        "aa:bb:cc:dd:ee:ff",
        &stats,
        10,
        20,
    );
    let parsed: serde_json::Value = serde_json::from_str(&compact).expect("Valid JSON");
    assert_eq!(parsed["Type"], "sock");
    assert_eq!(parsed["PID"], 42);
    assert_eq!(parsed["Comm"], hostile);
    assert_eq!(parsed["ESTAB"], 5);
    assert!(!parsed.as_object().unwrap().contains_key("PPID"));
}

#[test]
fn test_network_apply_socket_stats_event() {
    use std::sync::{Arc, Mutex};

    let net_stats: common::SharedNetStats = Arc::new(Mutex::new(HashMap::new()));

    // First event
    let mut e1 = panhandle_common::SocketStatsEvent::new(100);
    e1.tcp_established_delta = 1;
    e1.bytes_sent_delta = 1000;
    e1.packets_sent_delta = 1;
    common::apply_socket_stats_event(&net_stats, &e1);

    // Second event, same pid
    let mut e2 = panhandle_common::SocketStatsEvent::new(100);
    e2.tcp_established_delta = 1;
    e2.bytes_sent_delta = 500;
    e2.bytes_recv_delta = 2000;
    e2.packets_recv_delta = 3;
    e2.udp_sockets_set = 1;
    common::apply_socket_stats_event(&net_stats, &e2);

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
    let mut e3 = panhandle_common::SocketStatsEvent::new(100);
    e3.tcp_established_delta = -5;
    common::apply_socket_stats_event(&net_stats, &e3);
    assert_eq!(net_stats.lock().unwrap()[&100].tcp_established, 0);

    // udp_sockets_set is sticky
    let e4 = panhandle_common::SocketStatsEvent::new(100);
    common::apply_socket_stats_event(&net_stats, &e4);
    assert_eq!(net_stats.lock().unwrap()[&100].udp_sockets, 1);

    // Different pid gets independent entry
    let mut e5 = panhandle_common::SocketStatsEvent::new(200);
    e5.bytes_sent_delta = 42;
    common::apply_socket_stats_event(&net_stats, &e5);
    let map = net_stats.lock().unwrap();
    assert_eq!(map[&200].bytes_sent, 42);
    assert_eq!(map.len(), 2);
}

#[test]
fn test_network_prune_dead_pids() {
    use std::sync::{Arc, Mutex};

    let net_stats: common::SharedNetStats = Arc::new(Mutex::new(HashMap::from([
        (1, common::NetStats::default()),
        (2, common::NetStats::default()),
        (3, common::NetStats::default()),
    ])));

    common::prune_dead_pids(&net_stats, vec![2]);
    {
        let map = net_stats.lock().unwrap();
        assert_eq!(
            map.keys().copied().collect::<HashSet<_>>(),
            HashSet::from([1, 3])
        );
    }

    // Empty dead_pids changes nothing
    common::prune_dead_pids(&net_stats, vec![]);
    assert_eq!(net_stats.lock().unwrap().len(), 2);

    // Pruning non-existent pid is no-op
    common::prune_dead_pids(&net_stats, vec![999]);
    assert_eq!(net_stats.lock().unwrap().len(), 2);

    // Prune everything
    common::prune_dead_pids(&net_stats, vec![1, 3]);
    assert!(net_stats.lock().unwrap().is_empty());
}

#[test]
fn test_network_ip_to_interface() {
    use network_interface::{Addr, NetworkInterface, V4IfAddr, V6IfAddr};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let iface = NetworkInterface {
        name: "eth0".to_string(),
        addr: vec![
            Addr::V4(V4IfAddr {
                ip: Ipv4Addr::new(10, 0, 0, 5),
                broadcast: None,
                netmask: None,
            }),
            Addr::V6(V6IfAddr {
                ip: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                broadcast: None,
                netmask: None,
            }),
        ],
        mac_addr: Some("aa:bb:cc:dd:ee:ff".to_string()),
        index: 1,
        internal: false,
    };
    let interfaces = vec![iface];

    assert_eq!(
        common::ip_to_interface(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), &interfaces),
        Some(("eth0".to_string(), "10.0.0.5".to_string()))
    );
    assert_eq!(
        common::ip_to_interface(
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            &interfaces
        ),
        Some(("eth0".to_string(), "fe80::1".to_string()))
    );
    assert_eq!(
        common::ip_to_interface(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)), &interfaces),
        None
    );
}

#[test]
fn test_network_get_network_info_fallback() {
    use network_interface::{Addr, NetworkInterface, V4IfAddr};
    use std::net::Ipv4Addr;

    let nonexistent_pid = u32::MAX;

    // No interfaces -> fully unknown
    assert_eq!(
        common::get_network_info(nonexistent_pid, &[]),
        (
            "unknown".to_string(),
            "0.0.0.0".to_string(),
            "00:00:00:00:00:00".to_string()
        )
    );

    // Only "lo" -> still unknown (skipped)
    let lo = NetworkInterface {
        name: "lo".to_string(),
        addr: vec![Addr::V4(V4IfAddr {
            ip: Ipv4Addr::new(127, 0, 0, 1),
            broadcast: None,
            netmask: None,
        })],
        mac_addr: None,
        index: 1,
        internal: true,
    };
    assert_eq!(
        common::get_network_info(nonexistent_pid, std::slice::from_ref(&lo)),
        (
            "unknown".to_string(),
            "0.0.0.0".to_string(),
            "00:00:00:00:00:00".to_string()
        )
    );

    // Non-"lo" interface used as fallback
    let eth0 = NetworkInterface {
        name: "eth0".to_string(),
        addr: vec![Addr::V4(V4IfAddr {
            ip: Ipv4Addr::new(192, 168, 1, 10),
            broadcast: None,
            netmask: None,
        })],
        mac_addr: Some("11:22:33:44:55:66".to_string()),
        index: 2,
        internal: false,
    };
    assert_eq!(
        common::get_network_info(nonexistent_pid, &[lo, eth0]),
        (
            "eth0".to_string(),
            "192.168.1.10".to_string(),
            "11:22:33:44:55:66".to_string()
        )
    );
}

#[test]
fn test_helpers_output_needs() {
    assert_eq!(
        common::output_needs(false, false, false, false),
        (true, false)
    );
    assert_eq!(
        common::output_needs(false, false, false, true),
        (false, true)
    );
    assert_eq!(
        common::output_needs(true, false, false, false),
        (true, false)
    );
    assert_eq!(
        common::output_needs(true, false, true, false),
        (false, true)
    );
    assert_eq!(common::output_needs(true, false, true, true), (false, true));
    assert_eq!(
        common::output_needs(false, true, false, false),
        (true, false)
    );
    assert_eq!(
        common::output_needs(false, false, true, false),
        (false, true)
    );
    assert_eq!(
        common::output_needs(false, false, true, true),
        (false, true)
    );
}

#[test]
fn test_helpers_format_owner() {
    assert_eq!(
        common::format_owner(Some(0), Some("root")),
        ("0".to_string(), "root".to_string())
    );
    assert_eq!(
        common::format_owner(Some(1000), Some("dmcgee")),
        ("1000".to_string(), "dmcgee".to_string())
    );
    assert_eq!(
        common::format_owner(Some(100998), Some("unknown")),
        ("100998".to_string(), "unknown".to_string())
    );
    assert_eq!(
        common::format_owner(None, Some("unknown")),
        ("unknown".to_string(), "unknown".to_string())
    );
    assert_eq!(
        common::format_owner(None, None),
        ("unknown".to_string(), "unknown".to_string())
    );
}

#[test]
fn test_helpers_format_state() {
    assert_eq!(common::format_state(Some('R')), "R");
    assert_eq!(common::format_state(Some('S')), "S");
    assert_eq!(common::format_state(None), "");
}

#[test]
fn test_helpers_format_state_prose() {
    assert_eq!(common::format_state_prose(Some('R')), "running");
    assert_eq!(common::format_state_prose(Some('S')), "sleeping");
    assert_eq!(common::format_state_prose(Some('D')), "disk sleep");
    assert_eq!(common::format_state_prose(Some('Z')), "zombie");
    assert_eq!(common::format_state_prose(Some('T')), "stopped");
    assert_eq!(common::format_state_prose(Some('t')), "tracing stop");
    assert_eq!(common::format_state_prose(Some('X')), "dead");
    assert_eq!(common::format_state_prose(Some('I')), "idle");
    assert_eq!(common::format_state_prose(Some('P')), "parked");
    assert_eq!(common::format_state_prose(Some('?')), "unknown");
    assert_eq!(common::format_state_prose(None), "unknown");
}

#[test]
fn test_helpers_json_quoted() {
    assert_eq!(common::json_quoted("plain"), "\"plain\"");
    assert_eq!(common::json_quoted("say \"hi\""), "\"say \\\"hi\\\"\"");
    assert_eq!(common::json_quoted("a\\b"), "\"a\\\\b\"");
    assert_eq!(common::json_quoted("esc\u{1b}ape"), "\"esc\\u001bape\"");

    let hostile = "q\"\\\u{1b}\n\t";
    assert_eq!(
        common::json_quoted(hostile),
        serde_json::to_string(hostile).unwrap()
    );
    let roundtrip: String = serde_json::from_str(&common::json_quoted(hostile)).unwrap();
    assert_eq!(roundtrip, hostile);
}

#[test]
fn test_helpers_calc_delta() {
    assert_eq!(common::calc_delta(1_000_000_000, None), 0);
    assert_eq!(common::calc_delta(0, None), 0);
    assert_eq!(common::calc_delta(100, Some(40)), 60);
    assert_eq!(common::calc_delta(50, Some(50)), 0);
    assert_eq!(common::calc_delta(100, Some(150)), 0);
}

#[test]
fn test_helpers_event_matches_executable_filter() {
    assert!(common::event_matches_executable_filter(&[], "/usr/bin/ssh"));
    assert!(common::event_matches_executable_filter(&[], ""));

    let filter = vec!["/usr/bin/ssh".to_string(), "/usr/bin/scp".to_string()];
    assert!(common::event_matches_executable_filter(
        &filter,
        "/usr/bin/ssh"
    ));
    assert!(common::event_matches_executable_filter(
        &filter,
        "/usr/bin/scp"
    ));
    assert!(!common::event_matches_executable_filter(
        &filter,
        "/usr/bin/ls"
    ));
    assert!(!common::event_matches_executable_filter(
        &filter, "/usr/bin"
    ));
    assert!(!common::event_matches_executable_filter(&filter, "ssh"));
    assert!(!common::event_matches_executable_filter(&filter, ""));
}

#[test]
fn test_helpers_get_canonical_executable_list() {
    use std::os::unix::fs::symlink;

    let base = std::env::temp_dir().join(format!(
        "panhandle_test_geel_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&base).unwrap();

    let real_file = base.join("mybin");
    std::fs::write(&real_file, b"").unwrap();

    let symlink_path = base.join("mybin_link");
    symlink(&real_file, &symlink_path).unwrap();

    let nonexistent = base.join("does_not_exist");

    let input = vec![
        symlink_path.to_string_lossy().to_string(),
        nonexistent.to_string_lossy().to_string(),
    ];

    let result = common::get_canonical_executable_list(&input);

    assert!(result.contains(&symlink_path.to_string_lossy().to_string()));
    let canonical_real = std::fs::canonicalize(&real_file).unwrap();
    assert!(result.contains(&canonical_real.to_string_lossy().to_string()));
    assert!(result.contains(&nonexistent.to_string_lossy().to_string()));
    assert_eq!(result.len(), 3);

    let empty_input: Vec<String> = Vec::new();
    assert!(common::get_canonical_executable_list(&empty_input).is_empty());

    std::fs::remove_dir_all(&base).ok();
}

#[test]
fn test_helpers_resolve_comm_list_mode() {
    assert_eq!(
        common::resolve_comm_list_mode(&None, &None),
        Ok((common::NO_LIST, Vec::new()))
    );

    let deny = Some(vec!["bash".to_string()]);
    assert_eq!(
        common::resolve_comm_list_mode(&deny, &None),
        Ok((common::DENY_LIST, vec!["bash".to_string()]))
    );

    let allow = Some(vec!["sh".to_string()]);
    assert_eq!(
        common::resolve_comm_list_mode(&None, &allow),
        Ok((common::ALLOW_LIST, vec!["sh".to_string()]))
    );

    let empty_deny = Some(Vec::new());
    assert_eq!(
        common::resolve_comm_list_mode(&empty_deny, &None),
        Ok((common::DENY_LIST, Vec::new()))
    );

    let empty_allow = Some(Vec::new());
    assert_eq!(
        common::resolve_comm_list_mode(&None, &empty_allow),
        Ok((common::ALLOW_LIST, Vec::new()))
    );

    assert!(common::resolve_comm_list_mode(&deny, &allow).is_err());
}

#[test]
fn test_helpers_validate_count() {
    assert!(
        common::validate_count(
            common::EXECUTABLE_COUNT,
            common::EXECUTABLE_COUNT,
            "executables"
        )
        .is_ok()
    );
    assert!(
        common::validate_count(
            common::EXECUTABLE_COUNT + 1,
            common::EXECUTABLE_COUNT,
            "executables"
        )
        .is_err()
    );
    assert!(common::validate_count(common::UID_COUNT, common::UID_COUNT, "UIDs").is_ok());
    assert!(common::validate_count(common::UID_COUNT + 1, common::UID_COUNT, "UIDs").is_err());
    assert!(
        common::validate_count(
            common::MAX_BLOCKED_PATHS,
            common::MAX_BLOCKED_PATHS,
            "block-paths entries"
        )
        .is_ok()
    );
    assert!(
        common::validate_count(
            common::MAX_BLOCKED_PATHS + 1,
            common::MAX_BLOCKED_PATHS,
            "block-paths entries"
        )
        .is_err()
    );
    assert!(
        common::validate_count(
            common::MAX_BLOCKED_COMMS,
            common::MAX_BLOCKED_COMMS,
            "comm-allow/comm-deny entries"
        )
        .is_ok()
    );
    assert!(
        common::validate_count(
            common::MAX_BLOCKED_COMMS + 1,
            common::MAX_BLOCKED_COMMS,
            "comm-allow/comm-deny entries"
        )
        .is_err()
    );
}

#[test]
fn test_helpers_validate_count_error_message() {
    let err = common::validate_count(
        common::EXECUTABLE_COUNT + 1,
        common::EXECUTABLE_COUNT,
        "executables",
    )
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "Configuration error: The number of executables requested to monitor exceeds the maximum of {}",
            common::EXECUTABLE_COUNT
        )
    );

    let err = common::validate_count(common::UID_COUNT + 1, common::UID_COUNT, "UIDs").unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "Configuration error: The number of UIDs requested to monitor exceeds the maximum of {}",
            common::UID_COUNT
        )
    );
}

#[tokio::test]
async fn test_helpers_validate_syslog() {
    // Local syslog
    assert!(common::validate_syslog("unix").await.is_ok());
    assert!(common::validate_syslog("/dev/log").await.is_ok());

    // TCP with local listener
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let valid_addr_tcp = format!("localhost:{port}/tcp");
    assert!(common::validate_syslog(&valid_addr_tcp).await.is_ok());
    drop(listener);

    // UDP is connectionless
    assert!(common::validate_syslog("localhost:9/udp").await.is_ok());

    // Invalid hostname
    let addr_invalid_hostname = "nonexistent-host.invalid:514/tcp";
    let result = common::validate_syslog(addr_invalid_hostname).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Invalid remote address hostname provided")
    );

    // Unreachable TCP port
    let closed_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let addr_invalid_port = format!("localhost:{closed_port}/tcp");
    let result = common::validate_syslog(&addr_invalid_port).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Provided TCP port number is not reachable")
    );

    // General invalid
    let result = common::validate_syslog("something_invalid/tc").await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Invalid syslog argument")
    );
}

#[tokio::test]
async fn test_helpers_validate_url() {
    assert!(
        common::validate_url("http://localhost:4319/raw-audit")
            .await
            .is_ok()
    );
    assert!(common::validate_url("https://example.com").await.is_ok());
    assert!(common::validate_url("ftp://example.com").await.is_ok());
    assert!(common::validate_url("").await.is_err());
    assert!(common::validate_url("example.com").await.is_err());
    assert!(common::validate_url("http://").await.is_err());
    assert!(common::validate_url("//example.com/path").await.is_err());
    assert!(common::validate_url("www.invalid.com").await.is_err());
}

#[test]
fn test_helpers_resolve_username() {
    let pid = std::process::id();
    let uid = common::get_process_uid(pid).expect("status should succeed");
    assert!(!common::resolve_username(uid).is_empty());
    assert_eq!(common::resolve_username(u32::MAX), "unknown");
}

#[test]
fn test_procfs_helpers_format_faults_prose() {
    // Test format_faults_prose verbose
    let verbose = common::format_faults_prose(
        true,
        42,
        "bash",
        Some(1),
        Some("systemd"),
        Some(0),
        Some("root"),
        Some('S'),
        100,
        50,
    );
    assert!(verbose.contains("Type: fault"));
    assert!(verbose.contains("PID: 42"));
    assert!(verbose.contains("Comm: bash"));
    assert!(verbose.contains("Parent PID: 1"));
    assert!(verbose.contains("Parent Comm: systemd"));
    assert!(verbose.contains("User ID: 0"));
    assert!(verbose.contains("User: root"));
    assert!(verbose.contains("State: sleeping"));
    assert!(verbose.contains("Major Faults: 100"));
    assert!(verbose.contains("Child Major Faults: 50"));

    // Test format_faults_prose compact
    let compact =
        common::format_faults_prose(false, 42, "bash", None, None, None, None, None, 100, 50);
    assert!(compact.contains("Type: fault"));
    assert!(compact.contains("PID: 42"));
    assert!(compact.contains("Comm: bash"));
    assert!(compact.contains("Major Faults: 100"));
    assert!(compact.contains("Child Major Faults: 50"));
    assert!(!compact.contains("Parent PID"));
}

#[test]
fn test_procfs_helpers_format_faults_json() {
    let hostile = "bash\"\\\u{1b}[31m";

    // Test format_faults_json verbose
    let verbose = common::format_faults_json(
        true,
        42,
        hostile,
        Some(1),
        Some("systemd"),
        Some(0),
        Some("root"),
        Some('S'),
        100,
        50,
    );
    let parsed: serde_json::Value = serde_json::from_str(&verbose).expect("Valid JSON");
    assert_eq!(parsed["Type"], "fault");
    assert_eq!(parsed["PID"], 42);
    assert_eq!(parsed["Comm"], hostile);
    assert_eq!(parsed["PPID"], 1);
    assert_eq!(parsed["Parent_Comm"], "systemd");
    assert_eq!(parsed["UID"], "0");
    assert_eq!(parsed["Username"], "root");
    assert_eq!(parsed["State"], "S");
    assert_eq!(parsed["Maj_Faults"], 100);
    assert_eq!(parsed["Child_Maj_Faults"], 50);

    // Test format_faults_json compact
    let compact =
        common::format_faults_json(false, 42, hostile, None, None, None, None, None, 100, 50);
    let parsed: serde_json::Value = serde_json::from_str(&compact).expect("Valid JSON");
    assert_eq!(parsed["Type"], "fault");
    assert_eq!(parsed["PID"], 42);
    assert_eq!(parsed["Comm"], hostile);
    assert_eq!(parsed["Maj_Faults"], 100);
    assert!(!parsed.as_object().unwrap().contains_key("PPID"));
}

#[test]
fn test_procfs_helpers_format_mem_prose() {
    // Test format_mem_prose verbose
    let verbose = common::format_mem_prose(
        true,
        42,
        "bash",
        Some(1),
        Some("systemd"),
        Some(0),
        Some("root"),
        Some('S'),
        100,
        25000,
        200,
        500,
        50,
        30,
    );
    assert!(verbose.contains("Type: mem"));
    assert!(verbose.contains("PID: 42"));
    assert!(verbose.contains("Comm: bash"));
    assert!(verbose.contains("Parent PID: 1"));
    assert!(verbose.contains("Parent Comm: systemd"));
    assert!(verbose.contains("User ID: 0"));
    assert!(verbose.contains("User: root"));
    assert!(verbose.contains("State: sleeping"));
    assert!(verbose.contains("RSS: 100 MB (25000 pages)"));
    assert!(verbose.contains("Peak RSS: 200 MB"));
    assert!(verbose.contains("Virtual Size: 500 MB"));
    assert!(verbose.contains("Shared: 50 MB"));
    assert!(verbose.contains("Data + Stack: 30 MB"));

    // Test format_mem_prose compact
    let compact = common::format_mem_prose(
        false, 42, "bash", None, None, None, None, None, 100, 25000, 200, 500, 50, 30,
    );
    assert!(compact.contains("Type: mem"));
    assert!(compact.contains("PID: 42"));
    assert!(compact.contains("Comm: bash"));
    assert!(compact.contains("RSS: 100 MB (25000 pages)"));
    assert!(compact.contains("Peak RSS: 200 MB"));
    assert!(!compact.contains("Parent PID"));
}

#[test]
fn test_procfs_helpers_format_mem_json() {
    let hostile = "bash\"\\\u{1b}[31m";

    // Test format_mem_json verbose
    let verbose = common::format_mem_json(
        true,
        42,
        hostile,
        Some(1),
        Some("systemd"),
        Some(0),
        Some("root"),
        Some('S'),
        100,
        25000,
        200,
        500,
        50,
        30,
    );
    let parsed: serde_json::Value = serde_json::from_str(&verbose).expect("Valid JSON");
    assert_eq!(parsed["Type"], "mem");
    assert_eq!(parsed["PID"], 42);
    assert_eq!(parsed["Comm"], hostile);
    assert_eq!(parsed["PPID"], 1);
    assert_eq!(parsed["Parent_Comm"], "systemd");
    assert_eq!(parsed["UID"], "0");
    assert_eq!(parsed["Username"], "root");
    assert_eq!(parsed["State"], "S");
    assert_eq!(parsed["RSS_MB"], 100);
    assert_eq!(parsed["RSS_Pages"], 25000);
    assert_eq!(parsed["Peak_RSS_MB"], 200);
    assert_eq!(parsed["VSize_MB"], 500);
    assert_eq!(parsed["Shared_MB"], 50);
    assert_eq!(parsed["Data_Stack_Size_MB"], 30);

    // Test format_mem_json compact
    let compact = common::format_mem_json(
        false, 42, hostile, None, None, None, None, None, 100, 25000, 200, 500, 50, 30,
    );
    let parsed: serde_json::Value = serde_json::from_str(&compact).expect("Valid JSON");
    assert_eq!(parsed["Type"], "mem");
    assert_eq!(parsed["PID"], 42);
    assert_eq!(parsed["Comm"], hostile);
    assert_eq!(parsed["RSS_MB"], 100);
    assert!(!parsed.as_object().unwrap().contains_key("PPID"));
}
