//! Tests for OutputConfig formatting methods (format_shell_event_json/text, format_execve_event_json/text)

use panhandle::output::OutputConfig;
use panhandle_common::{
    ARG_COUNT, ARG_SIZE, ENV_COUNT, ENV_SIZE, ExecveEvent, LEN_MAX_PATH, Readline,
};
use reqwest::Client;
use std::sync::Arc;

#[tokio::test]
async fn test_output_config_new() {
    let hostname = Arc::new("test-host".to_string());
    let client = Client::new();

    let output = OutputConfig::new(
        hostname.clone(),
        false, // json
        false, // http
        false, // syslog
        Arc::new("unix".to_string()),
        Arc::new("http://localhost:8080".to_string()),
        false, // debug
        client,
    )
    .expect("OutputConfig::new should succeed");

    assert!(!output.json);
    assert!(!output.http);
    assert!(!output.syslog);
    assert_eq!(output.hostname.as_str(), "test-host");
}

#[test]
fn test_format_shell_event_json() {
    let hostname = Arc::new("test-host".to_string());
    let client = Client::new();

    let output = OutputConfig::new(
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

    // Create a test Readline event
    let mut entry = [0u8; ARG_SIZE];
    let text = b"echo hello";
    entry[..text.len()].copy_from_slice(text);

    let mut command = [0u8; 16];
    command[..4].copy_from_slice(b"bash");

    let event = Readline {
        timestamp: 1_700_000_000_000_000_000, // Fixed timestamp for deterministic test
        uid: 1000,
        gid: 100,
        pid: 42,
        tgid: 42,
        command,
        entry,
    };

    let json = output.format_shell_event_json(&event, "test-monitor");

    // Verify it's valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should be valid JSON");

    // Check key fields
    assert_eq!(parsed["type"], "shell");
    assert_eq!(parsed["shell_type"], "test-monitor");
    assert_eq!(parsed["uid"], 1000);
    assert_eq!(parsed["gid"], 100);
    assert_eq!(parsed["pid"], 42);
    assert_eq!(parsed["tgid"], 42);
    assert_eq!(parsed["command"], "bash");
    assert_eq!(parsed["entry"], "echo hello");
    assert!(parsed["timestamp"].is_string());
    assert_eq!(parsed["hostname"], "test-host");
}

#[test]
fn test_format_shell_event_json_with_hostile_chars() {
    let hostname = Arc::new("test-host".to_string());
    let client = Client::new();

    let output = OutputConfig::new(
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

    // Create a test Readline event with hostile characters
    let mut entry = [0u8; ARG_SIZE];
    let text = br#"echo "hello" \u001b"#;
    entry[..text.len()].copy_from_slice(text);

    let mut command = [0u8; 16];
    command[..4].copy_from_slice(b"bash");

    let event = Readline {
        timestamp: 1_700_000_000_000_000_000,
        uid: 1000,
        gid: 100,
        pid: 42,
        tgid: 42,
        command,
        entry,
    };

    let json = output.format_shell_event_json(&event, "test-monitor");

    // Verify it's valid JSON and hostile chars are escaped
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should be valid JSON");
    assert_eq!(parsed["entry"], r#"echo "hello" \u001b"#);
}

#[test]
fn test_format_shell_event_text() {
    let hostname = Arc::new("test-host".to_string());
    let client = Client::new();

    let output = OutputConfig::new(
        hostname.clone(),
        false, // json
        false, // http
        false, // syslog
        Arc::new("unix".to_string()),
        Arc::new("http://localhost:8080".to_string()),
        false, // debug
        client,
    )
    .expect("OutputConfig::new should succeed");

    let mut entry = [0u8; ARG_SIZE];
    let text = b"ls -la";
    entry[..text.len()].copy_from_slice(text);

    let mut command = [0u8; 16];
    command[..4].copy_from_slice(b"bash");

    let event = Readline {
        timestamp: 1_700_000_000_000_000_000,
        uid: 1000,
        gid: 100,
        pid: 42,
        tgid: 42,
        command,
        entry,
    };

    let text_output = output.format_shell_event_text(&event, "test-monitor");

    // Check format: "timestamp [monitor] command: entry (uid)"
    assert!(text_output.contains("test-monitor"));
    assert!(text_output.contains("bash"));
    assert!(text_output.contains("ls -la"));
    assert!(text_output.contains("1000"));
}

#[test]
fn test_format_execve_event_json() {
    let hostname = Arc::new("test-host".to_string());
    let client = Client::new();

    let output = OutputConfig::new(
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

    // Create a test ExecveEvent
    let mut filename = [0u8; LEN_MAX_PATH];
    let fname = b"/bin/ls";
    filename[..fname.len()].copy_from_slice(fname);

    let mut command = [0u8; 16];
    command[..2].copy_from_slice(b"ls");

    let mut argv = [[0u8; ARG_SIZE]; ARG_COUNT];
    argv[0][..2].copy_from_slice(b"ls");
    argv[1][..3].copy_from_slice(b"-la");

    let mut envp = [[0u8; ENV_SIZE]; ENV_COUNT];
    envp[0][..5].copy_from_slice(b"PATH=");

    let event = ExecveEvent {
        timestamp: 1_700_000_000_000_000_000,
        argv,
        envp,
        pid: 42,
        gid: 100,
        uid: 1000,
        tgid: 42,
        command,
        filename,
    };

    let json = output.format_execve_event_json(&event, "execve");

    // Verify it's valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should be valid JSON");

    // Check key fields
    assert_eq!(parsed["type"], "execve");
    assert_eq!(parsed["monitor"], "execve");
    assert_eq!(parsed["uid"], 1000);
    assert_eq!(parsed["gid"], 100);
    assert_eq!(parsed["pid"], 42);
    assert_eq!(parsed["tgid"], 42);
    assert_eq!(parsed["command"], "ls");
    assert_eq!(parsed["filename"], "/bin/ls");
    assert_eq!(parsed["args"], serde_json::json!(["ls", "-la"]));
    assert_eq!(parsed["envs"], serde_json::json!(["PATH="]));
    assert!(parsed["timestamp"].is_string());
    assert_eq!(parsed["hostname"], "test-host");
}

#[test]
fn test_format_execve_event_json_with_hostile_chars() {
    let hostname = Arc::new("test-host".to_string());
    let client = Client::new();

    let output = OutputConfig::new(
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

    // Create a test ExecveEvent with hostile characters in args/envs
    let mut filename = [0u8; LEN_MAX_PATH];
    let fname = b"/bin/echo";
    filename[..fname.len()].copy_from_slice(fname);

    let mut command = [0u8; 16];
    command[..4].copy_from_slice(b"echo");

    let mut argv = [[0u8; ARG_SIZE]; ARG_COUNT];
    argv[0][..4].copy_from_slice(b"echo");
    argv[1][..7].copy_from_slice(br#""hello""#);

    let mut envp = [[0u8; ENV_SIZE]; ENV_COUNT];
    envp[0][..10].copy_from_slice(b"TERM=xterm");

    let event = ExecveEvent {
        timestamp: 1_700_000_000_000_000_000,
        argv,
        envp,
        pid: 42,
        gid: 100,
        uid: 1000,
        tgid: 42,
        command,
        filename,
    };

    let json = output.format_execve_event_json(&event, "execve");

    // Verify it's valid JSON and hostile chars are escaped
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should be valid JSON");
    assert_eq!(parsed["args"], serde_json::json!(["echo", r#""hello""#]));
}

#[test]
fn test_format_execve_event_text() {
    let hostname = Arc::new("test-host".to_string());
    let client = Client::new();

    let output = OutputConfig::new(
        hostname.clone(),
        false, // json
        false, // http
        false, // syslog
        Arc::new("unix".to_string()),
        Arc::new("http://localhost:8080".to_string()),
        false, // debug
        client,
    )
    .expect("OutputConfig::new should succeed");

    let mut filename = [0u8; LEN_MAX_PATH];
    let fname = b"/bin/ls";
    filename[..fname.len()].copy_from_slice(fname);

    let mut command = [0u8; 16];
    command[..2].copy_from_slice(b"ls");

    let mut argv = [[0u8; ARG_SIZE]; ARG_COUNT];
    argv[0][..2].copy_from_slice(b"ls");
    argv[1][..3].copy_from_slice(b"-la");

    let mut envp = [[0u8; ENV_SIZE]; ENV_COUNT];
    envp[0][..5].copy_from_slice(b"PATH=");

    let event = ExecveEvent {
        timestamp: 1_700_000_000_000_000_000,
        argv,
        envp,
        pid: 42,
        gid: 100,
        uid: 1000,
        tgid: 42,
        command,
        filename,
    };

    let text_output = output.format_execve_event_text(&event, "execve");

    // Check format: "timestamp [monitor] command: filename=..., args=[...], uid=..."
    assert!(text_output.contains("execve"));
    assert!(text_output.contains("ls"));
    assert!(text_output.contains("/bin/ls"));
    assert!(text_output.contains(r#"["ls", "-la"]"#));
    assert!(text_output.contains("1000"));
}

#[tokio::test]
async fn test_output_event_no_channels() {
    let hostname = Arc::new("test-host".to_string());
    let client = Client::new();

    let output = OutputConfig::new(
        hostname.clone(),
        false, // json
        false, // http
        false, // syslog
        Arc::new("unix".to_string()),
        Arc::new("http://localhost:8080".to_string()),
        false, // debug
        client,
    )
    .expect("OutputConfig::new should succeed");

    // Should not panic or error when no channels enabled
    let result = output
        .output_event(r#"{"test": "json"}"#, "test text")
        .await;
    assert!(result.is_ok());
}

#[test]
fn test_output_config_json_vs_text_selection() {
    let hostname = Arc::new("test-host".to_string());
    let client = Client::new();

    // Test with json=true
    let output_json = OutputConfig::new(
        hostname.clone(),
        true,  // json
        false, // http
        false, // syslog
        Arc::new("unix".to_string()),
        Arc::new("http://localhost:8080".to_string()),
        false, // debug
        client.clone(),
    )
    .expect("OutputConfig::new should succeed");

    assert!(output_json.json);

    // Test with json=false
    let output_text = OutputConfig::new(
        hostname.clone(),
        false, // json
        false, // http
        false, // syslog
        Arc::new("unix".to_string()),
        Arc::new("http://localhost:8080".to_string()),
        false, // debug
        client,
    )
    .expect("OutputConfig::new should succeed");

    assert!(!output_text.json);
}

#[test]
fn test_format_shell_event_json_zeroed() {
    let hostname = Arc::new("test-host".to_string());
    let client = Client::new();

    let output = OutputConfig::new(
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

    // Zeroed event
    let event = Readline {
        timestamp: 0,
        uid: 0,
        gid: 0,
        pid: 0,
        tgid: 0,
        command: [0u8; 16],
        entry: [0u8; ARG_SIZE],
    };

    let json = output.format_shell_event_json(&event, "test-monitor");

    // Should produce valid JSON even with zeroed data
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should be valid JSON");
    assert_eq!(parsed["uid"], 0);
    assert_eq!(parsed["entry"], "");
    assert_eq!(parsed["command"], "");
}

#[test]
fn test_format_execve_event_json_zeroed() {
    let hostname = Arc::new("test-host".to_string());
    let client = Client::new();

    let output = OutputConfig::new(
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

    // Zeroed event
    let event = ExecveEvent {
        timestamp: 0,
        argv: [[0u8; ARG_SIZE]; ARG_COUNT],
        envp: [[0u8; ENV_SIZE]; ENV_COUNT],
        pid: 0,
        gid: 0,
        uid: 0,
        tgid: 0,
        command: [0u8; 16],
        filename: [0u8; LEN_MAX_PATH],
    };

    let json = output.format_execve_event_json(&event, "execve");

    // Should produce valid JSON even with zeroed data
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should be valid JSON");
    assert_eq!(parsed["uid"], 0);
    assert_eq!(parsed["filename"], "");
    assert_eq!(parsed["command"], "");
    assert_eq!(parsed["args"], serde_json::json!([]));
    assert_eq!(parsed["envs"], serde_json::json!([]));
}
