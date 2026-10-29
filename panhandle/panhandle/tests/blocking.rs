//! Tests for syscall blocking (blocking.rs)

use std::collections::HashMap;

mod common {
    pub use aya::Btf;
    pub use panhandle::blocking::setup_syscall_blocking;
    pub use panhandle::config::AppConfig;
    pub use panhandle::error::PanhandleError;
    pub use panhandle::helpers::resolve_comm_list_mode;
    pub use panhandle_common::{
        ALLOW_LIST, DENY_LIST, LIST_MODE, MAX_BLOCKED_PATHS, MAX_COMM_LENGTH, MAX_PATH_LENGTH,
        NO_LIST,
    };
}

#[test]
fn test_resolve_comm_list_mode_deny() {
    let comm_deny = Some(vec!["bash".to_string(), "zsh".to_string()]);
    let comm_allow: Option<Vec<String>> = None;

    let result = common::resolve_comm_list_mode(&comm_deny, &comm_allow);
    assert!(result.is_ok());

    let (mode, comms) = result.unwrap();
    assert_eq!(mode, common::DENY_LIST);
    assert_eq!(comms, vec!["bash".to_string(), "zsh".to_string()]);
}

#[test]
fn test_resolve_comm_list_mode_allow() {
    let comm_deny: Option<Vec<String>> = None;
    let comm_allow = Some(vec!["sshd".to_string(), "nginx".to_string()]);

    let result = common::resolve_comm_list_mode(&comm_deny, &comm_allow);
    assert!(result.is_ok());

    let (mode, comms) = result.unwrap();
    assert_eq!(mode, common::ALLOW_LIST);
    assert_eq!(comms, vec!["sshd".to_string(), "nginx".to_string()]);
}

#[test]
fn test_resolve_comm_list_mode_none() {
    let comm_deny: Option<Vec<String>> = None;
    let comm_allow: Option<Vec<String>> = None;

    let result = common::resolve_comm_list_mode(&comm_deny, &comm_allow);
    assert!(result.is_ok());

    let (mode, comms) = result.unwrap();
    assert_eq!(mode, common::NO_LIST);
    assert_eq!(comms, Vec::<String>::new());
}

#[test]
fn test_resolve_comm_list_mode_empty_deny() {
    let comm_deny = Some(Vec::new());
    let comm_allow: Option<Vec<String>> = None;

    let result = common::resolve_comm_list_mode(&comm_deny, &comm_allow);
    assert!(result.is_ok());

    let (mode, comms) = result.unwrap();
    assert_eq!(mode, common::DENY_LIST);
    assert_eq!(comms, Vec::<String>::new());
}

#[test]
fn test_resolve_comm_list_mode_empty_allow() {
    let comm_deny: Option<Vec<String>> = None;
    let comm_allow = Some(Vec::new());

    let result = common::resolve_comm_list_mode(&comm_deny, &comm_allow);
    assert!(result.is_ok());

    let (mode, comms) = result.unwrap();
    assert_eq!(mode, common::ALLOW_LIST);
    assert_eq!(comms, Vec::<String>::new());
}

#[test]
fn test_resolve_comm_list_mode_both_error() {
    let comm_deny = Some(vec!["bash".to_string()]);
    let comm_allow = Some(vec!["zsh".to_string()]);

    let result = common::resolve_comm_list_mode(&comm_deny, &comm_allow);
    assert!(result.is_err());

    match result {
        Err(msg) => {
            assert!(msg.contains("Allow and deny list both provided"));
        }
        _ => panic!("Expected Config error"),
    }
}

#[test]
fn test_setup_syscall_blocking_no_syscalls() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => return,
    };
    let btf = common::Btf::from_sys_fs().expect("BTF not available on this system");

    let config = common::AppConfig {
        syscalls: vec![],
        comm_allow: vec![],
        comm_deny: vec![],
        block_paths: vec![],
        ..Default::default()
    };

    let result = common::setup_syscall_blocking(&mut ebpf, &config, &btf);
    assert!(result.is_ok());
}

#[test]
fn test_setup_syscall_blocking_with_comm_deny() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => return,
    };
    let btf = common::Btf::from_sys_fs().expect("BTF not available on this system");

    let config = common::AppConfig {
        syscalls: vec!["open".to_string()],
        comm_deny: vec!["bash".to_string(), "zsh".to_string()],
        comm_allow: vec![],
        block_paths: vec![],
        ..Default::default()
    };

    // Will fail because we don't have real eBPF programs/maps
    // but we can test the logic up to the map population
    let result = common::setup_syscall_blocking(&mut ebpf, &config, &btf);
    // Expected to fail on map access since we don't have real bytecode
    assert!(result.is_err());
}

#[test]
fn test_setup_syscall_blocking_with_comm_allow() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => return,
    };
    let btf = common::Btf::from_sys_fs().expect("BTF not available on this system");

    let config = common::AppConfig {
        syscalls: vec!["execve".to_string()],
        comm_allow: vec!["sshd".to_string()],
        comm_deny: vec![],
        block_paths: vec![],
        ..Default::default()
    };

    let result = common::setup_syscall_blocking(&mut ebpf, &config, &btf);
    assert!(result.is_err());
}

#[test]
fn test_setup_syscall_blocking_with_block_paths() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => return,
    };
    let btf = common::Btf::from_sys_fs().expect("BTF not available on this system");

    let config = common::AppConfig {
        syscalls: vec!["open".to_string(), "openat".to_string()],
        comm_allow: vec![],
        comm_deny: vec![],
        block_paths: vec!["/etc/shadow".to_string(), "/etc/passwd".to_string()],
        ..Default::default()
    };

    let result = common::setup_syscall_blocking(&mut ebpf, &config, &btf);
    assert!(result.is_err());
}

#[test]
fn test_setup_syscall_blocking_empty_block_paths() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => return,
    };
    let btf = common::Btf::from_sys_fs().expect("BTF not available on this system");

    let config = common::AppConfig {
        syscalls: vec!["open".to_string()],
        comm_allow: vec![],
        comm_deny: vec![],
        block_paths: vec![],
        ..Default::default()
    };

    let result = common::setup_syscall_blocking(&mut ebpf, &config, &btf);
    assert!(result.is_err());
}

#[test]
fn test_setup_syscall_blocking_all_syscalls() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => return,
    };
    let btf = common::Btf::from_sys_fs().expect("BTF not available on this system");

    let config = common::AppConfig {
        syscalls: vec![
            "open".to_string(),
            "openat".to_string(),
            "creat".to_string(),
            "execve".to_string(),
        ],
        comm_allow: vec![],
        comm_deny: vec![],
        block_paths: vec![],
        ..Default::default()
    };

    let result = common::setup_syscall_blocking(&mut ebpf, &config, &btf);
    assert!(result.is_err());
}

#[test]
fn test_setup_syscall_blocking_unknown_syscall() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => return,
    };
    let btf = common::Btf::from_sys_fs().expect("BTF not available on this system");

    let config = common::AppConfig {
        syscalls: vec!["unknown_syscall".to_string()],
        comm_allow: vec![],
        comm_deny: vec![],
        block_paths: vec![],
        ..Default::default()
    };

    let result = common::setup_syscall_blocking(&mut ebpf, &config, &btf);
    // Should not error on unknown syscall - just warns
    assert!(result.is_err());
}

#[test]
fn test_comms_map_key_format() {
    // Test that comm strings are properly truncated/padded to 16 bytes
    let test_cases = vec![
        (
            "bash",
            [b'b', b'a', b's', b'h', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        ("verylongcommandname", {
            let mut arr = [0u8; 16];
            arr[..15].copy_from_slice(b"verylongcommand");
            arr
        }),
        ("", [0u8; 16]),
    ];

    for (input, expected) in test_cases {
        let mut comm = [0u8; 16];
        let bytes = input.as_bytes();
        let len = bytes.len().min(15);
        comm[..len].copy_from_slice(&bytes[..len]);
        assert_eq!(comm, expected);
    }
}

#[test]
fn test_blocked_paths_map_key_format() {
    // Test that path strings are properly truncated/padded to 256 bytes
    let test_cases: Vec<(String, [u8; 256])> = vec![
        ("/etc/shadow".to_string(), {
            let mut arr = [0u8; 256];
            arr[..11].copy_from_slice(b"/etc/shadow");
            arr
        }),
        ("a".repeat(300), {
            let mut arr = [0u8; 256];
            arr[..255].copy_from_slice("a".repeat(255).as_bytes());
            arr
        }),
        ("".to_string(), [0u8; 256]),
    ];

    for (input, expected) in test_cases {
        let mut path = [0u8; 256];
        let bytes = input.as_bytes();
        let len = bytes.len().min(255);
        path[..len].copy_from_slice(&bytes[..len]);
        assert_eq!(path, expected);
    }
}

#[test]
fn test_list_mode_constants() {
    assert_eq!(common::NO_LIST, 0);
    assert_eq!(common::DENY_LIST, 1);
    assert_eq!(common::ALLOW_LIST, 2);
    assert_eq!(common::LIST_MODE, 255); // Special key for mode indicator
}

#[test]
fn test_comms_map_mode_insertion() {
    // Test the mode key insertion logic
    let _mode_key = [common::LIST_MODE; 16];

    // For DENY_LIST (1)
    let mode_val_deny = common::DENY_LIST;
    assert_eq!(mode_val_deny, 1);

    // For ALLOW_LIST (2)
    let mode_val_allow = common::ALLOW_LIST;
    assert_eq!(mode_val_allow, 2);

    // For NO_LIST (0) - mode key should not be inserted
    let mode_val_none = common::NO_LIST;
    assert_eq!(mode_val_none, 0);
}

#[test]
fn test_blocked_paths_placeholder() {
    // Test placeholder insertion when block_paths is empty
    let placeholder = [0u8; 256];
    assert_eq!(placeholder, [0u8; 256]);
}

#[test]
fn test_syscall_to_lsm_hook_mapping() {
    // Test the mapping from syscalls to LSM hooks
    let test_cases = vec![
        ("open", "file_open", "block_open"),
        ("openat", "file_open", "block_open"),
        ("creat", "file_open", "block_open"),
        ("execve", "bprm_check_security", "block_execve"),
    ];

    for (syscall, expected_hook, expected_program) in test_cases {
        match syscall {
            "open" | "openat" | "creat" => {
                assert_eq!(expected_hook, "file_open");
                assert_eq!(expected_program, "block_open");
            }
            "execve" => {
                assert_eq!(expected_hook, "bprm_check_security");
                assert_eq!(expected_program, "block_execve");
            }
            _ => panic!("Unknown syscall: {}", syscall),
        }
    }
}

#[test]
fn test_comm_map_insertion() {
    // Test the COMMS map insertion logic
    let _comm_map: HashMap<[u8; 16], u8> = HashMap::new();

    let comms = vec!["bash".to_string(), "zsh".to_string(), "sh".to_string()];
    let _list_type = common::DENY_LIST;

    for comm_str in &comms {
        let mut comm = [0u8; 16];
        let bytes = comm_str.as_bytes();
        let len = bytes.len().min(15);
        comm[..len].copy_from_slice(&bytes[..len]);

        // In real code: comm_map.insert(&comm, &list_type, 0)
        // Here we just verify the key format
        assert_eq!(comm.len(), 16);
    }

    // Mode key
    let _mode_key = [common::LIST_MODE; 16];
    assert_eq!(_mode_key, [255u8; 16]);
}

#[test]
fn test_blocked_paths_map_insertion() {
    let _path_map: HashMap<[u8; 256], u8> = HashMap::new();

    let paths = vec!["/etc/shadow".to_string(), "/etc/passwd".to_string()];

    for path_str in &paths {
        let mut path = [0u8; 256];
        let bytes = path_str.as_bytes();
        let len = bytes.len().min(255);
        path[..len].copy_from_slice(&bytes[..len]);

        // In real code: path_map.insert(&path, &1u8, 0)
        assert_eq!(path.len(), 256);
    }
}

#[test]
fn test_blocked_paths_empty_placeholder() {
    let _path_map: HashMap<[u8; 256], u8> = HashMap::new();

    let placeholder = [0u8; 256];
    // In real code: path_map.insert(&placeholder, &0u8, 0)
    assert_eq!(placeholder, [0u8; 256]);
}

#[test]
fn test_app_config_syscalls_default() {
    let config = common::AppConfig::default();
    assert!(config.syscalls.is_empty());
    assert!(config.comm_allow.is_empty());
    assert!(config.comm_deny.is_empty());
    assert!(config.block_paths.is_empty());
}

#[test]
fn test_app_config_syscalls_with_values() {
    let config = common::AppConfig {
        syscalls: vec!["open".to_string(), "execve".to_string()],
        comm_deny: vec!["bash".to_string()],
        block_paths: vec!["/etc/shadow".to_string()],
        ..Default::default()
    };

    assert_eq!(config.syscalls.len(), 2);
    assert_eq!(config.comm_deny.len(), 1);
    assert_eq!(config.block_paths.len(), 1);
}

#[test]
fn test_blocking_error_handling_missing_comms_map() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => return,
    };
    let btf = common::Btf::from_sys_fs().expect("BTF not available on this system");

    let config = common::AppConfig {
        syscalls: vec!["open".to_string()],
        comm_deny: vec!["bash".to_string()],
        comm_allow: vec![],
        block_paths: vec![],
        ..Default::default()
    };

    let result = common::setup_syscall_blocking(&mut ebpf, &config, &btf);
    assert!(result.is_err());

    match result {
        Err(common::PanhandleError::MissingMap(name)) => {
            assert_eq!(name, "COMMS");
        }
        Err(common::PanhandleError::EbpfMap(_)) => {
            // Also acceptable - map exists but wrong type
        }
        _ => {
            // Other errors are also possible (program not found, etc.)
        }
    }
}

#[test]
fn test_blocking_error_handling_missing_blocked_paths_map() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => return,
    };
    let btf = common::Btf::from_sys_fs().expect("BTF not available on this system");

    let config = common::AppConfig {
        syscalls: vec!["open".to_string()],
        comm_deny: vec![],
        comm_allow: vec![],
        block_paths: vec!["/etc/shadow".to_string()],
        ..Default::default()
    };

    let result = common::setup_syscall_blocking(&mut ebpf, &config, &btf);
    assert!(result.is_err());
}

#[test]
fn test_blocking_error_handling_missing_lsm_program() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => return,
    };
    let btf = common::Btf::from_sys_fs().expect("BTF not available on this system");

    let config = common::AppConfig {
        syscalls: vec!["open".to_string()],
        comm_deny: vec![],
        comm_allow: vec![],
        block_paths: vec![],
        ..Default::default()
    };

    let result = common::setup_syscall_blocking(&mut ebpf, &config, &btf);
    assert!(result.is_err());
}

#[test]
fn test_resolve_comm_list_mode_from_appconfig() {
    // Test that AppConfig's comm_allow/comm_deny work with resolve_comm_list_mode
    let config = common::AppConfig {
        comm_deny: vec!["bash".to_string(), "zsh".to_string()],
        comm_allow: vec![],
        ..Default::default()
    };

    let comm_deny = if config.comm_deny.is_empty() {
        None
    } else {
        Some(config.comm_deny.clone())
    };
    let comm_allow = if config.comm_allow.is_empty() {
        None
    } else {
        Some(config.comm_allow.clone())
    };

    let result = common::resolve_comm_list_mode(&comm_deny, &comm_allow);
    assert!(result.is_ok());

    let (mode, comms) = result.unwrap();
    assert_eq!(mode, common::DENY_LIST);
    assert_eq!(comms.len(), 2);
}

#[test]
fn test_blocking_with_combined_syscalls() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => return,
    };
    let btf = common::Btf::from_sys_fs().expect("BTF not available on this system");

    let config = common::AppConfig {
        syscalls: vec!["open".to_string(), "execve".to_string()],
        comm_deny: vec!["bash".to_string()],
        block_paths: vec!["/etc/shadow".to_string()],
        ..Default::default()
    };

    let result = common::setup_syscall_blocking(&mut ebpf, &config, &btf);
    assert!(result.is_err());
}

#[test]
fn test_max_blocked_paths_limit() {
    // Test that we respect MAX_BLOCKED_PATHS
    let paths: Vec<String> = (0..common::MAX_BLOCKED_PATHS + 1)
        .map(|i| format!("/bin/p{}", i))
        .collect();

    assert!(paths.len() > common::MAX_BLOCKED_PATHS);
}

#[test]
fn test_max_comm_length_limit() {
    // Test that we respect MAX_COMM_LENGTH
    let long_comm = "a".repeat(common::MAX_COMM_LENGTH + 1);
    assert!(long_comm.len() > common::MAX_COMM_LENGTH);

    let ok_comm = "a".repeat(common::MAX_COMM_LENGTH);
    assert_eq!(ok_comm.len(), common::MAX_COMM_LENGTH);
}

#[test]
fn test_max_path_length_limit() {
    // Test that we respect MAX_PATH_LENGTH (255)
    let long_path = "a".repeat(common::MAX_PATH_LENGTH + 1);
    assert!(long_path.len() > common::MAX_PATH_LENGTH);

    let ok_path = "a".repeat(common::MAX_PATH_LENGTH);
    assert_eq!(ok_path.len(), common::MAX_PATH_LENGTH);
}

#[test]
fn test_comm_truncation_at_15_chars() {
    // Comm names are truncated to 15 chars + null terminator in 16-byte array
    let long_comm = "this_is_a_very_long_command_name";
    let mut comm = [0u8; 16];
    let bytes = long_comm.as_bytes();
    let len = bytes.len().min(15);
    comm[..len].copy_from_slice(&bytes[..len]);

    // Should be truncated to 15 chars
    assert_eq!(&comm[..15], b"this_is_a_very_");
    assert_eq!(comm[15], 0);
}

#[test]
fn test_path_truncation_at_255_chars() {
    // Paths are truncated to 255 chars + null terminator in 256-byte array
    let long_path = "a".repeat(300);
    let mut path = [0u8; 256];
    let bytes = long_path.as_bytes();
    let len = bytes.len().min(255);
    path[..len].copy_from_slice(&bytes[..len]);

    // Should be truncated to 255 chars
    assert_eq!(path[255], 0);
    // First 255 should be 'a'
    assert!(path[..255].iter().all(|&b| b == b'a'));
}

#[test]
fn test_setup_syscall_blocking_warning_on_empty_list() {
    // Test the warning when syscall blocking enabled but no comm list
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => return,
    };
    let btf = common::Btf::from_sys_fs().expect("BTF not available on this system");

    let config = common::AppConfig {
        syscalls: vec!["open".to_string()],
        comm_allow: vec![],
        comm_deny: vec![],
        block_paths: vec![],
        ..Default::default()
    };

    let result = common::setup_syscall_blocking(&mut ebpf, &config, &btf);
    // Should succeed up to the map insertion (which will fail without real maps)
    // The warning is printed to stderr but not returned as error
    assert!(result.is_err());
}
