//! Tests for error paths in main.rs, config.rs, helpers.rs

use clap::Parser;
use panhandle::config::{PanhandleConfig, ShellConfig};
use panhandle::helpers::{
    calc_delta, event_matches_executable_filter, format_owner, format_state, format_state_prose,
    get_canonical_executable_list, get_parent_pid, get_process_name, get_process_uid, json_quoted,
    output_needs, read_ring_item, resolve_comm_list_mode, resolve_username, validate_count,
    validate_syslog, validate_url,
};
use panhandle::input_configs::{ConfigArgs, RawArgs};
use panhandle::monitors::MonitorContext;
use panhandle::output::OutputConfig;
use panhandle_common::*;
use reqwest::Client;
use std::path::PathBuf;
use std::sync::Arc;

mod common {
    pub use panhandle::config::AppConfig;
    pub use panhandle::error::PanhandleError;
    pub use panhandle::input_configs::{
        load_config_args, merge_args, should_run_default_execve_monitor,
    };
}

#[tokio::test]
async fn test_load_config_args_file_not_found() {
    let result = common::load_config_args("/nonexistent/path/config.yaml".to_string()).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Config file not found"));
}

#[tokio::test]
async fn test_load_config_args_invalid_json() {
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_path = temp_dir.path().join("test_invalid.json");
    std::fs::write(&temp_path, "{ invalid json").unwrap();

    let result = common::load_config_args(temp_path.to_string_lossy().to_string()).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    eprintln!("Error for invalid_json: {}", err);
    assert!(err.contains("Invalid JSON config"));
    assert!(err.contains(&temp_path.to_string_lossy().to_string()));
}

#[tokio::test]
async fn test_load_config_args_invalid_yaml() {
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_path = temp_dir.path().join("test_invalid.yaml");
    std::fs::write(&temp_path, "invalid: [unclosed").unwrap();

    let result = common::load_config_args(temp_path.to_string_lossy().to_string()).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Invalid YAML config"));
    assert!(err.contains(&temp_path.to_string_lossy().to_string()));
}

#[tokio::test]
async fn test_load_config_args_unknown_field() {
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_path = temp_dir.path().join("test_unknown.yaml");
    std::fs::write(&temp_path, "unknown_field: true\n").unwrap();

    let result = common::load_config_args(temp_path.to_string_lossy().to_string()).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("unknown field") || err.contains("Invalid YAML config"));
    assert!(err.contains(&temp_path.to_string_lossy().to_string()));
}

#[tokio::test]
async fn test_load_config_args_unsupported_extension() {
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_path = temp_dir.path().join("test_config.xml");
    std::fs::write(&temp_path, "<config></config>").unwrap();

    let result = common::load_config_args(temp_path.to_string_lossy().to_string()).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Unsupported config type"));
    // Note: Unsupported config type error doesn't include the path
}

#[tokio::test]
async fn test_load_config_args_empty_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_path = temp_dir.path().join("test_empty.yaml");
    std::fs::write(&temp_path, "").unwrap();

    let result = common::load_config_args(temp_path.to_string_lossy().to_string()).await;
    // Empty YAML/JSON files may fail to deserialize, so just check it doesn't panic
    let _ = result;
}

#[tokio::test]
async fn test_load_config_args_partial_config() {
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_path = temp_dir.path().join("test_partial.json");
    std::fs::write(&temp_path, r#"{"verbose": true, "exclude_min_uid": 1000}"#).unwrap();

    let result = common::load_config_args(temp_path.to_string_lossy().to_string()).await;
    assert!(result.is_ok());

    let config = result.unwrap();
    assert!(config.verbose);
    assert_eq!(config.exclude_min_uid, Some(1000));
}

#[tokio::test]
async fn test_merge_args_overrides_cli_values() {
    let config = ConfigArgs {
        exclude_min_uid: Some(1),
        exclude_max_uid: Some(500),
        executables: Some(vec!["/bin/old".to_string()]),
        ..Default::default()
    };

    let cli = RawArgs {
        exclude_min_uid: Some(2),
        exclude_max_uid: Some(600),
        executables: Some(vec!["/bin/new".to_string()]),
        ..Default::default()
    };

    let merged = common::merge_args(cli, config).await;

    assert_eq!(merged.exclude_min_uid, Some(2));
    assert_eq!(merged.exclude_max_uid, Some(600));
    assert_eq!(merged.executables, Some(vec!["/bin/new".to_string()]));
}

#[tokio::test]
async fn test_merge_args_preserves_config_when_cli_unset() {
    let config = ConfigArgs {
        pid_list: Some(vec![42]),
        syscalls: Some(vec!["execve".to_string()]),
        block_paths: Some(vec!["/etc/shadow".to_string()]),
        comm_allow: Some(vec!["sshd".to_string()]),
        ..Default::default()
    };

    let cli = RawArgs::default();
    let merged = common::merge_args(cli, config).await;

    assert_eq!(merged.pid_list, Some(vec![42]));
    assert_eq!(merged.syscalls, Some(vec!["execve".to_string()]));
    assert_eq!(merged.block_paths, Some(vec!["/etc/shadow".to_string()]));
    assert_eq!(merged.comm_allow, Some(vec!["sshd".to_string()]));
}

#[tokio::test]
async fn test_merge_args_creates_outputs_when_config_has_none() {
    let config = ConfigArgs::default();
    let cli = RawArgs {
        file: Some(PathBuf::from("/tmp/panhandle.log")),
        http: Some("http://localhost:4319/raw-audit".to_string()),
        syslog: Some(Some("localhost:514/tcp".to_string())),
        ..Default::default()
    };

    let merged = common::merge_args(cli, config).await;

    assert_eq!(merged.file, Some(PathBuf::from("/tmp/panhandle.log")));
    assert_eq!(
        merged.http,
        Some("http://localhost:4319/raw-audit".to_string())
    );
    assert_eq!(merged.syslog, Some(Some("localhost:514/tcp".to_string())));
}

#[tokio::test]
async fn test_merge_args_output_partial_update() {
    let config = ConfigArgs {
        file: Some(PathBuf::from("/var/log/panhandle/panhandle.log")),
        syslog: Some(Some("hpcsyslog.lanl.gov:514/tcp".to_string())),
        ..Default::default()
    };

    let cli = RawArgs {
        syslog: Some(Some("unix".to_string())),
        ..Default::default()
    };

    let merged = common::merge_args(cli, config).await;

    assert_eq!(
        merged.file,
        Some(PathBuf::from("/var/log/panhandle/panhandle.log"))
    );
    assert_eq!(merged.syslog, Some(Some("unix".to_string())));
}

#[tokio::test]
async fn test_merge_args_adds_cli_output_type_absent_from_config() {
    let config = ConfigArgs {
        file: Some(PathBuf::from("/var/log/panhandle/panhandle.log")),
        syslog: Some(Some("hpcsyslog.lanl.gov:514/tcp".to_string())),
        ..Default::default()
    };

    let cli = RawArgs {
        http: Some("http://localhost:4319/raw-audit".to_string()),
        ..Default::default()
    };

    let merged = common::merge_args(cli, config).await;

    assert_eq!(
        merged.file,
        Some(PathBuf::from("/var/log/panhandle/panhandle.log"))
    );
    assert_eq!(
        merged.syslog,
        Some(Some("hpcsyslog.lanl.gov:514/tcp".to_string()))
    );
    assert_eq!(
        merged.http,
        Some("http://localhost:4319/raw-audit".to_string())
    );
}

#[tokio::test]
async fn test_merge_args_bool_flags_cli_wins() {
    let config = ConfigArgs {
        debug: true,
        verbose: true,
        json: true,
        bash: true,
        ..Default::default()
    };

    // CLI defaults are false, so they shouldn't override config's true
    let cli = RawArgs::default();
    let merged = common::merge_args(cli, config).await;

    assert!(merged.debug);
    assert!(merged.verbose);
    assert!(merged.json);
    assert!(merged.bash);
}

#[tokio::test]
async fn test_merge_args_bool_flags_cli_false_preserves_config_true() {
    let config = ConfigArgs {
        debug: true,
        verbose: true,
        json: true,
        ..Default::default()
    };

    let cli = RawArgs {
        debug: false, // CLI explicitly false
        verbose: false,
        json: false,
        ..Default::default()
    };

    let merged = common::merge_args(cli, config).await;

    // CLI false should not override config true (only true overrides)
    assert!(merged.debug);
    assert!(merged.verbose);
    assert!(merged.json);
}

#[test]
fn test_should_run_default_execve_monitor_explicit() {
    let args = RawArgs {
        execve: true,
        cpu: true,
        ..Default::default()
    };
    assert!(common::should_run_default_execve_monitor(
        args.execve,
        args.bash,
        args.zsh,
        args.memory_faults.is_some(),
        args.socket,
        args.memory,
        args.cpu,
        args.gpu,
        args.io,
        args.syscalls.is_some()
    ));
}

#[test]
fn test_should_run_default_execve_monitor_fallback() {
    let args = RawArgs::default();
    assert!(common::should_run_default_execve_monitor(
        args.execve,
        args.bash,
        args.zsh,
        args.memory_faults.is_some(),
        args.socket,
        args.memory,
        args.cpu,
        args.gpu,
        args.io,
        args.syscalls.is_some()
    ));
}

#[test]
fn test_should_run_default_execve_monitor_disabled_by_cpu() {
    let args = RawArgs {
        cpu: true,
        ..Default::default()
    };
    assert!(!common::should_run_default_execve_monitor(
        args.execve,
        args.bash,
        args.zsh,
        args.memory_faults.is_some(),
        args.socket,
        args.memory,
        args.cpu,
        args.gpu,
        args.io,
        args.syscalls.is_some()
    ));
}

#[test]
fn test_should_run_default_execve_monitor_disabled_by_bash() {
    let args = RawArgs {
        bash: true,
        ..Default::default()
    };
    assert!(!common::should_run_default_execve_monitor(
        args.execve,
        args.bash,
        args.zsh,
        args.memory_faults.is_some(),
        args.socket,
        args.memory,
        args.cpu,
        args.gpu,
        args.io,
        args.syscalls.is_some()
    ));
}

#[test]
fn test_should_run_default_execve_monitor_disabled_by_zsh() {
    let args = RawArgs {
        zsh: true,
        ..Default::default()
    };
    assert!(!common::should_run_default_execve_monitor(
        args.execve,
        args.bash,
        args.zsh,
        args.memory_faults.is_some(),
        args.socket,
        args.memory,
        args.cpu,
        args.gpu,
        args.io,
        args.syscalls.is_some()
    ));
}

#[test]
fn test_should_run_default_execve_monitor_disabled_by_memory_faults() {
    let args = RawArgs {
        memory_faults: Some(1),
        ..Default::default()
    };
    assert!(!common::should_run_default_execve_monitor(
        args.execve,
        args.bash,
        args.zsh,
        args.memory_faults.is_some(),
        args.socket,
        args.memory,
        args.cpu,
        args.gpu,
        args.io,
        args.syscalls.is_some()
    ));
}

#[test]
fn test_should_run_default_execve_monitor_disabled_by_socket() {
    let args = RawArgs {
        socket: true,
        ..Default::default()
    };
    assert!(!common::should_run_default_execve_monitor(
        args.execve,
        args.bash,
        args.zsh,
        args.memory_faults.is_some(),
        args.socket,
        args.memory,
        args.cpu,
        args.gpu,
        args.io,
        args.syscalls.is_some()
    ));
}

#[test]
fn test_should_run_default_execve_monitor_disabled_by_memory() {
    let args = RawArgs {
        memory: true,
        ..Default::default()
    };
    assert!(!common::should_run_default_execve_monitor(
        args.execve,
        args.bash,
        args.zsh,
        args.memory_faults.is_some(),
        args.socket,
        args.memory,
        args.cpu,
        args.gpu,
        args.io,
        args.syscalls.is_some()
    ));
}

#[test]
fn test_should_run_default_execve_monitor_disabled_by_gpu() {
    let args = RawArgs {
        gpu: true,
        ..Default::default()
    };
    assert!(!common::should_run_default_execve_monitor(
        args.execve,
        args.bash,
        args.zsh,
        args.memory_faults.is_some(),
        args.socket,
        args.memory,
        args.cpu,
        args.gpu,
        args.io,
        args.syscalls.is_some()
    ));
}

#[test]
fn test_should_run_default_execve_monitor_disabled_by_io() {
    let args = RawArgs {
        io: true,
        ..Default::default()
    };
    assert!(!common::should_run_default_execve_monitor(
        args.execve,
        args.bash,
        args.zsh,
        args.memory_faults.is_some(),
        args.socket,
        args.memory,
        args.cpu,
        args.gpu,
        args.io,
        args.syscalls.is_some()
    ));
}

#[test]
fn test_should_run_default_execve_monitor_disabled_by_syscalls() {
    let args = RawArgs {
        syscalls: Some(vec!["execve".to_string()]),
        ..Default::default()
    };
    assert!(!common::should_run_default_execve_monitor(
        args.execve,
        args.bash,
        args.zsh,
        args.memory_faults.is_some(),
        args.socket,
        args.memory,
        args.cpu,
        args.gpu,
        args.io,
        args.syscalls.is_some()
    ));
}

#[test]
fn test_app_config_validate_uid_range() {
    let config = common::AppConfig {
        exclude_min_uid: 500,
        exclude_max_uid: 100,
        ..Default::default()
    };

    let result = config.validate_uid_range();
    assert!(result.is_err());
    match result {
        Err(common::PanhandleError::UidValidation(msg)) => {
            assert!(msg.contains("must not be greater than"));
        }
        _ => panic!("Expected UidValidation error"),
    }
}

#[test]
fn test_app_config_validate_uid_range_ok() {
    let config = common::AppConfig {
        exclude_min_uid: 100,
        exclude_max_uid: 500,
        ..Default::default()
    };

    let result = config.validate_uid_range();
    assert!(result.is_ok());
}

#[test]
fn test_app_config_validate_include_uids() {
    let config = common::AppConfig {
        include_uids: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], // 11 > UID_COUNT (10)
        ..Default::default()
    };

    let result = config.validate_include_uids();
    assert!(result.is_err());
    match result {
        Err(common::PanhandleError::UidValidation(msg)) => {
            assert!(msg.contains("Too many include UIDs"));
        }
        _ => panic!("Expected UidValidation error"),
    }
}

#[test]
fn test_app_config_validate_include_uids_ok() {
    let config = common::AppConfig {
        include_uids: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10], // 10 == UID_COUNT
        ..Default::default()
    };

    let result = config.validate_include_uids();
    assert!(result.is_ok());
}

#[test]
fn test_app_config_validate_executables() {
    let config = common::AppConfig {
        executables: vec!["/bin/1".to_string(); 21], // 21 > EXECUTABLE_COUNT (20)
        ..Default::default()
    };

    let result = config.validate_executables();
    assert!(result.is_err());
    match result {
        Err(common::PanhandleError::InvalidArgument(msg)) => {
            assert!(msg.contains("Too many executables"));
        }
        _ => panic!("Expected InvalidArgument error"),
    }
}

#[test]
fn test_app_config_validate_executables_ok() {
    let config = common::AppConfig {
        executables: vec!["/bin/1".to_string(); 20], // 20 == EXECUTABLE_COUNT
        ..Default::default()
    };

    let result = config.validate_executables();
    assert!(result.is_ok());
}

#[test]
fn test_app_config_validate_block_paths() {
    let config = common::AppConfig {
        block_paths: vec!["/path".to_string(); 65], // 65 > MAX_BLOCKED_PATHS (64)
        ..Default::default()
    };

    let result = config.validate_block_paths();
    assert!(result.is_err());
    match result {
        Err(common::PanhandleError::PathValidation(msg)) => {
            assert!(msg.contains("Too many block paths"));
        }
        _ => panic!("Expected PathValidation error"),
    }
}

#[test]
fn test_app_config_validate_block_paths_ok() {
    let config = common::AppConfig {
        block_paths: vec!["/path".to_string(); 64], // 64 == MAX_BLOCKED_PATHS
        ..Default::default()
    };

    let result = config.validate_block_paths();
    assert!(result.is_ok());
}

#[test]
fn test_app_config_validate_comm_lists_both_provided() {
    let config = common::AppConfig {
        comm_allow: vec!["bash".to_string()],
        comm_deny: vec!["zsh".to_string()],
        ..Default::default()
    };

    let result = config.validate_comm_lists();
    assert!(result.is_err());
    match result {
        Err(common::PanhandleError::CommValidation(msg)) => {
            assert!(msg.contains("Cannot specify both --comm-allow and --comm-deny"));
        }
        _ => panic!("Expected CommValidation error"),
    }
}

#[test]
fn test_app_config_validate_comm_lists_too_many() {
    let config = common::AppConfig {
        comm_allow: vec!["c".to_string(); 65], // 65 > MAX_BLOCKED_COMMS (64)
        comm_deny: vec![],
        ..Default::default()
    };

    let result = config.validate_comm_lists();
    assert!(result.is_err());
    match result {
        Err(common::PanhandleError::CommValidation(msg)) => {
            assert!(msg.contains("Too many comm entries"));
        }
        _ => panic!("Expected CommValidation error"),
    }
}

#[test]
fn test_app_config_validate_comm_lists_length() {
    let config = common::AppConfig {
        comm_allow: vec!["a".repeat(16)], // 16 > MAX_COMM_LENGTH (15)
        comm_deny: vec![],
        ..Default::default()
    };

    let result = config.validate_comm_lists();
    assert!(result.is_err());
    match result {
        Err(common::PanhandleError::CommValidation(msg)) => {
            assert!(msg.contains("exceeds max length"));
        }
        _ => panic!("Expected CommValidation error"),
    }
}

#[test]
fn test_app_config_validate_comm_lists_ok() {
    let config = common::AppConfig {
        comm_allow: vec!["bash".to_string(), "zsh".to_string()],
        comm_deny: vec![],
        ..Default::default()
    };

    let result = config.validate_comm_lists();
    assert!(result.is_ok());
}

#[test]
fn test_app_config_validate_block_path_lengths() {
    let config = common::AppConfig {
        block_paths: vec!["a".repeat(256)], // 256 > MAX_PATH_LENGTH (255)
        ..Default::default()
    };

    let result = config.validate_block_path_lengths();
    assert!(result.is_err());
    match result {
        Err(common::PanhandleError::PathValidation(msg)) => {
            assert!(msg.contains("exceeds max length"));
        }
        _ => panic!("Expected PathValidation error"),
    }
}

#[test]
fn test_app_config_validate_block_path_lengths_ok() {
    let config = common::AppConfig {
        block_paths: vec!["a".repeat(255)], // 255 == MAX_PATH_LENGTH
        ..Default::default()
    };

    let result = config.validate_block_path_lengths();
    assert!(result.is_ok());
}

#[test]
fn test_app_config_validate_syscalls() {
    let config = common::AppConfig {
        syscalls: vec!["invalid_syscall".to_string()],
        ..Default::default()
    };

    let result = config.validate_all();
    assert!(result.is_err());
    match result {
        Err(common::PanhandleError::InvalidArgument(msg)) => {
            assert!(msg.contains("Invalid syscall"));
        }
        _ => panic!("Expected InvalidArgument error"),
    }
}

#[test]
fn test_app_config_validate_syscalls_ok() {
    let config = common::AppConfig {
        syscalls: vec![
            "open".to_string(),
            "openat".to_string(),
            "creat".to_string(),
            "execve".to_string(),
        ],
        ..Default::default()
    };

    let result = config.validate_all();
    assert!(result.is_ok());
}

#[test]
fn test_app_config_validate_poll_zero() {
    let config = common::AppConfig {
        poll_seconds: 0,
        ..Default::default()
    };

    let result = config.validate_all();
    assert!(result.is_err());
    match result {
        Err(common::PanhandleError::InvalidArgument(msg)) => {
            assert!(msg.contains("--poll must be at least 1"));
        }
        _ => panic!("Expected InvalidArgument error"),
    }
}

#[test]
fn test_app_config_validate_all_ok() {
    let config = common::AppConfig::default();
    let result = config.validate_all();
    assert!(result.is_ok());
}

#[test]
fn test_app_config_build_global_configs() {
    let config = common::AppConfig {
        shells: true,
        exclude_min_uid: 100,
        exclude_max_uid: 999,
        include_uids: vec![1000, 1001],
        ..Default::default()
    };

    let (panhandle_config, shell_config) = config.build_global_configs();

    assert_eq!(panhandle_config.shells, 1);
    assert_eq!(panhandle_config.exclude_min_uid, 100);
    assert_eq!(panhandle_config.exclude_max_uid, 999);
    assert_eq!(panhandle_config.include_enabled, 1);
    assert_eq!(panhandle_config.include_uids[0], 1000);
    assert_eq!(panhandle_config.include_uids[1], 1001);

    assert_eq!(shell_config.shells, 1);
    assert_eq!(shell_config.exclude_min_uid, 100);
    assert_eq!(shell_config.exclude_max_uid, 999);
    assert_eq!(shell_config.include_enabled, 1);
    assert_eq!(shell_config.include_uids[0], 1000);
    assert_eq!(shell_config.include_uids[1], 1001);
}

#[test]
fn test_app_config_build_global_configs_no_include_uids() {
    let config = common::AppConfig {
        shells: true,
        exclude_min_uid: 100,
        exclude_max_uid: 999,
        include_uids: vec![],
        ..Default::default()
    };

    let (panhandle_config, shell_config) = config.build_global_configs();

    assert_eq!(panhandle_config.include_enabled, 0);
    assert_eq!(panhandle_config.include_uids, [0u32; UID_COUNT]);

    assert_eq!(shell_config.include_enabled, 0);
    assert_eq!(shell_config.include_uids, [0u32; UID_COUNT]);
}

#[test]
fn test_helpers_validate_count_boundary() {
    // Test exact boundary
    assert!(validate_count(EXECUTABLE_COUNT, EXECUTABLE_COUNT, "executables").is_ok());
    assert!(validate_count(EXECUTABLE_COUNT + 1, EXECUTABLE_COUNT, "executables").is_err());

    assert!(validate_count(UID_COUNT, UID_COUNT, "UIDs").is_ok());
    assert!(validate_count(UID_COUNT + 1, UID_COUNT, "UIDs").is_err());

    assert!(validate_count(MAX_BLOCKED_PATHS, MAX_BLOCKED_PATHS, "block-paths entries").is_ok());
    assert!(
        validate_count(
            MAX_BLOCKED_PATHS + 1,
            MAX_BLOCKED_PATHS,
            "block-paths entries"
        )
        .is_err()
    );

    assert!(
        validate_count(
            MAX_BLOCKED_COMMS,
            MAX_BLOCKED_COMMS,
            "comm-allow/comm-deny entries"
        )
        .is_ok()
    );
    assert!(
        validate_count(
            MAX_BLOCKED_COMMS + 1,
            MAX_BLOCKED_COMMS,
            "comm-allow/comm-deny entries"
        )
        .is_err()
    );
}

#[test]
fn test_helpers_validate_count_error_message() {
    let err = validate_count(EXECUTABLE_COUNT + 1, EXECUTABLE_COUNT, "executables").unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "Configuration error: The number of executables requested to monitor exceeds the maximum of {}",
            EXECUTABLE_COUNT
        )
    );

    let err = validate_count(UID_COUNT + 1, UID_COUNT, "UIDs").unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "Configuration error: The number of UIDs requested to monitor exceeds the maximum of {}",
            UID_COUNT
        )
    );
}

#[tokio::test]
async fn test_helpers_validate_syslog_errors() {
    // Invalid hostname
    let result = validate_syslog("nonexistent-host.invalid:514/tcp").await;
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
    let syslog_addr = format!("localhost:{}/tcp", closed_port);
    let result = validate_syslog(&syslog_addr).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Provided TCP port number is not reachable")
    );

    // General invalid format
    let result = validate_syslog("something_invalid/tc").await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Invalid syslog argument")
    );
}

#[tokio::test]
async fn test_helpers_validate_url_errors() {
    assert!(validate_url("").await.is_err());
    assert!(validate_url("example.com").await.is_err());
    assert!(validate_url("http://").await.is_err());
    assert!(validate_url("//example.com/path").await.is_err());
    assert!(validate_url("www.invalid.com").await.is_err());
}

#[test]
fn test_helpers_output_needs_all_combinations() {
    // (http, syslog, json_output, debug) -> (needs_plain, needs_json)
    assert_eq!(output_needs(false, false, false, false), (true, false));
    assert_eq!(output_needs(false, false, false, true), (false, true));
    assert_eq!(output_needs(true, false, false, false), (true, false));
    assert_eq!(output_needs(true, false, true, false), (false, true));
    assert_eq!(output_needs(true, false, true, true), (false, true));
    assert_eq!(output_needs(false, true, false, false), (true, false));
    assert_eq!(output_needs(false, false, true, false), (false, true));
    assert_eq!(output_needs(false, false, true, true), (false, true));
}

#[test]
fn test_helpers_event_matches_executable_filter() {
    assert!(event_matches_executable_filter(&[], "/usr/bin/ssh"));
    assert!(event_matches_executable_filter(&[], ""));

    let filter = vec!["/usr/bin/ssh".to_string(), "/usr/bin/scp".to_string()];
    assert!(event_matches_executable_filter(&filter, "/usr/bin/ssh"));
    assert!(event_matches_executable_filter(&filter, "/usr/bin/scp"));
    assert!(!event_matches_executable_filter(&filter, "/usr/bin/ls"));
    assert!(!event_matches_executable_filter(&filter, "/usr/bin"));
    assert!(!event_matches_executable_filter(&filter, "ssh"));
    assert!(!event_matches_executable_filter(&filter, ""));
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

    let result = get_canonical_executable_list(&input);

    assert!(result.contains(&symlink_path.to_string_lossy().to_string()));
    let canonical_real = std::fs::canonicalize(&real_file).unwrap();
    assert!(result.contains(&canonical_real.to_string_lossy().to_string()));
    assert!(result.contains(&nonexistent.to_string_lossy().to_string()));
    assert_eq!(result.len(), 3);

    let empty_input: Vec<String> = Vec::new();
    assert!(get_canonical_executable_list(&empty_input).is_empty());

    std::fs::remove_dir_all(&base).ok();
}

#[test]
fn test_helpers_resolve_comm_list_mode() {
    assert_eq!(
        resolve_comm_list_mode(&None, &None),
        Ok((NO_LIST, Vec::new()))
    );

    let deny = Some(vec!["bash".to_string()]);
    assert_eq!(
        resolve_comm_list_mode(&deny, &None),
        Ok((DENY_LIST, vec!["bash".to_string()]))
    );

    let allow = Some(vec!["sh".to_string()]);
    assert_eq!(
        resolve_comm_list_mode(&None, &allow),
        Ok((ALLOW_LIST, vec!["sh".to_string()]))
    );

    let empty_deny = Some(Vec::new());
    assert_eq!(
        resolve_comm_list_mode(&empty_deny, &None),
        Ok((DENY_LIST, Vec::new()))
    );

    let empty_allow = Some(Vec::new());
    assert_eq!(
        resolve_comm_list_mode(&None, &empty_allow),
        Ok((ALLOW_LIST, Vec::new()))
    );

    assert!(resolve_comm_list_mode(&deny, &allow).is_err());
}

#[test]
fn test_helpers_format_owner() {
    assert_eq!(
        format_owner(Some(0), Some("root")),
        ("0".to_string(), "root".to_string())
    );
    assert_eq!(
        format_owner(Some(1000), Some("dmcgee")),
        ("1000".to_string(), "dmcgee".to_string())
    );
    assert_eq!(
        format_owner(Some(100998), Some("unknown")),
        ("100998".to_string(), "unknown".to_string())
    );
    assert_eq!(
        format_owner(None, Some("unknown")),
        ("unknown".to_string(), "unknown".to_string())
    );
    assert_eq!(
        format_owner(None, None),
        ("unknown".to_string(), "unknown".to_string())
    );
}

#[test]
fn test_helpers_format_state() {
    assert_eq!(format_state(Some('R')), "R");
    assert_eq!(format_state(Some('S')), "S");
    assert_eq!(format_state(None), "");
}

#[test]
fn test_helpers_format_state_prose() {
    assert_eq!(format_state_prose(Some('R')), "running");
    assert_eq!(format_state_prose(Some('S')), "sleeping");
    assert_eq!(format_state_prose(Some('D')), "disk sleep");
    assert_eq!(format_state_prose(Some('Z')), "zombie");
    assert_eq!(format_state_prose(Some('T')), "stopped");
    assert_eq!(format_state_prose(Some('t')), "tracing stop");
    assert_eq!(format_state_prose(Some('X')), "dead");
    assert_eq!(format_state_prose(Some('I')), "idle");
    assert_eq!(format_state_prose(Some('P')), "parked");
    assert_eq!(format_state_prose(Some('?')), "unknown");
    assert_eq!(format_state_prose(None), "unknown");
}

#[test]
fn test_helpers_json_quoted() {
    assert_eq!(json_quoted("plain"), "\"plain\"");
    assert_eq!(json_quoted("say \"hi\""), "\"say \\\"hi\\\"\"");
    assert_eq!(json_quoted("a\\b"), "\"a\\\\b\"");
    assert_eq!(json_quoted("esc\u{1b}ape"), "\"esc\\u001bape\"");

    let hostile = "q\"\\\u{1b}\n\t";
    assert_eq!(
        json_quoted(hostile),
        serde_json::to_string(hostile).unwrap()
    );
    let roundtrip: String = serde_json::from_str(&json_quoted(hostile)).unwrap();
    assert_eq!(roundtrip, hostile);
}

#[test]
fn test_helpers_calc_delta() {
    assert_eq!(calc_delta(1_000_000_000, None), 0);
    assert_eq!(calc_delta(0, None), 0);
    assert_eq!(calc_delta(100, Some(40)), 60);
    assert_eq!(calc_delta(50, Some(50)), 0);
    assert_eq!(calc_delta(100, Some(150)), 0);
}

#[test]
fn test_helpers_get_process_name() {
    let pid = std::process::id();
    let name = get_process_name(pid);
    assert!(name.is_some_and(|n| !n.is_empty()));

    assert_eq!(get_process_name(u32::MAX), None);
}

#[test]
fn test_helpers_get_parent_pid() {
    let pid = std::process::id();
    let ppid = get_parent_pid(pid).expect("stat should succeed for the current process");

    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let expected_ppid: u32 = status
        .lines()
        .find_map(|l| l.strip_prefix("PPid:"))
        .expect("PPid field should be present in /proc/self/status")
        .trim()
        .parse()
        .unwrap();
    assert_eq!(ppid, expected_ppid);

    assert!(get_parent_pid(u32::MAX).is_err());
}

#[test]
fn test_helpers_get_process_uid() {
    let pid = std::process::id();
    let uid = get_process_uid(pid).expect("status should succeed for the current process");

    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let expected_uid: u32 = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .expect("Uid field should be present in /proc/self/status")
        .split_whitespace()
        .next()
        .expect("Uid field should have at least one value")
        .parse()
        .unwrap();
    assert_eq!(uid, expected_uid);

    assert_eq!(get_process_uid(u32::MAX), None);
}

#[test]
fn test_helpers_resolve_username() {
    let pid = std::process::id();
    let uid = get_process_uid(pid).expect("status should succeed for the current process");
    assert!(!resolve_username(uid).is_empty());

    assert_eq!(resolve_username(u32::MAX), "unknown");
}

#[test]
fn test_helpers_read_ring_item() {
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

    let reconstructed: TestEvent = unsafe { read_ring_item(bytes) };
    assert_eq!(original, reconstructed);
}

#[test]
fn test_helpers_read_ring_item_trailing_bytes() {
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

    let reconstructed: TestEvent = unsafe { read_ring_item(&bytes) };
    assert_eq!(original, reconstructed);
}

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

#[tokio::test]
async fn test_output_config_output_event_no_channels() {
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

    let result = output
        .output_event(r#"{"test": "json"}"#, "test text")
        .await;
    assert!(result.is_ok());
}

#[test]
fn test_raw_args_parse_defaults() {
    let args = RawArgs::try_parse_from(["panhandle"]).unwrap();
    assert!(!args.bash);
    assert!(!args.cpu);
    assert_eq!(args.poll, None);
    assert_eq!(args.executables, None);
}

#[test]
fn test_raw_args_parse_invalid_scalars() {
    assert!(RawArgs::try_parse_from(["panhandle", "--pid-list", "-1"]).is_err());
    assert!(RawArgs::try_parse_from(["panhandle", "--exclude-min-uid", "notanumber"]).is_err());
    assert!(RawArgs::try_parse_from(["panhandle", "--memory-faults", "-5"]).is_err());
}

#[test]
fn test_raw_args_parse_block_paths_length_boundary() {
    let at_limit = "a".repeat(MAX_PATH_LENGTH);
    assert!(RawArgs::try_parse_from(["panhandle", "--block-paths", &at_limit]).is_ok());

    let over_limit = "a".repeat(MAX_PATH_LENGTH + 1);
    assert!(RawArgs::try_parse_from(["panhandle", "--block-paths", &over_limit]).is_err());
}

#[test]
fn test_raw_args_parse_comm_length_boundary() {
    let at_limit = "a".repeat(MAX_COMM_LENGTH);
    assert!(RawArgs::try_parse_from(["panhandle", "--comm-allow", &at_limit]).is_ok());
    assert!(RawArgs::try_parse_from(["panhandle", "--comm-deny", &at_limit]).is_ok());

    let over_limit = "a".repeat(MAX_COMM_LENGTH + 1);
    assert!(RawArgs::try_parse_from(["panhandle", "--comm-allow", &over_limit]).is_err());
    assert!(RawArgs::try_parse_from(["panhandle", "--comm-deny", &over_limit]).is_err());
}

#[test]
fn test_raw_args_parse_poll_rejects_zero() {
    assert!(RawArgs::try_parse_from(["panhandle", "--poll", "0"]).is_err());
}

#[test]
fn test_panhandle_config_default() {
    let config = PanhandleConfig::default();
    assert_eq!(config.shells, 0);
    assert_eq!(config.exclude_min_uid, 0);
    assert_eq!(config.exclude_max_uid, 0);
    assert_eq!(config.include_enabled, 0);
    assert_eq!(config.include_uids, [0u32; UID_COUNT]);
}

#[test]
fn test_shell_config_default() {
    let config = ShellConfig::default();
    assert_eq!(config.shells, 0);
    assert_eq!(config.exclude_min_uid, 0);
    assert_eq!(config.exclude_max_uid, 0);
    assert_eq!(config.include_enabled, 0);
    assert_eq!(config.include_uids, [0u32; UID_COUNT]);
}

#[test]
fn test_panhandle_config_pod() {
    let config = PanhandleConfig::default();
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &config as *const _ as *const u8,
            core::mem::size_of::<PanhandleConfig>(),
        )
    };
    assert_eq!(bytes.len(), core::mem::size_of::<PanhandleConfig>());
}

#[test]
fn test_shell_config_pod() {
    let config = ShellConfig::default();
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &config as *const _ as *const u8,
            core::mem::size_of::<ShellConfig>(),
        )
    };
    assert_eq!(bytes.len(), core::mem::size_of::<ShellConfig>());
}

#[test]
fn test_monitor_context_creation() {
    let config = common::AppConfig::default();
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

    let ctx = MonitorContext::new(config, output);
    // Verify context can be created
    assert!(ctx.config.pid_list.is_empty());
}

#[test]
fn test_config_args_default() {
    let config = ConfigArgs::default();
    assert!(!config.bash);
    assert!(!config.debug);
    assert!(!config.execve);
    assert!(!config.json);
    assert!(!config.verbose);
    assert!(!config.zsh);
    assert!(!config.quiet);
    assert!(!config.shells);
    assert!(!config.socket);
    assert!(!config.io);
    assert!(!config.cpu);
    assert!(!config.gpu);
    assert!(!config.memory);
}

#[test]
fn test_raw_args_default() {
    let args = RawArgs::default();
    assert!(!args.bash);
    assert!(!args.debug);
    assert!(!args.execve);
    assert!(!args.json);
    assert!(!args.verbose);
    assert!(!args.zsh);
    assert!(!args.quiet);
    assert!(!args.shells);
    assert!(!args.socket);
    assert!(!args.io);
    assert!(!args.cpu);
    assert!(!args.gpu);
    assert!(!args.memory);
    assert_eq!(args.poll, None);
    assert_eq!(args.executables, None);
    assert_eq!(args.http, None);
    assert_eq!(args.syslog, None);
}
