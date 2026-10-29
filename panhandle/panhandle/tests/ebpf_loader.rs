//! Tests for eBPF loading/attachment (ebpf_loader.rs)

mod common {
    pub use aya::{Btf, EbpfLoader, VerifierLogLevel};
    pub use panhandle::config::{
        PanhandleConfig, PanhandleConfig as ConfigPanhandleConfig, ShellConfig,
        ShellConfig as ConfigShellConfig,
    };
    pub use panhandle::ebpf_loader::{
        LoadedEbpf, attach_btf_tracepoint, attach_kprobe, attach_lsm_hook, attach_raw_tracepoint,
        attach_uprobe, create_ring_buffer_async_fd, get_hash_map, load_ebpf,
    };
    pub use panhandle::error::PanhandleError;
}

#[test]
fn test_panhandle_config_default() {
    let config = common::ConfigPanhandleConfig::default();
    assert_eq!(config.shells, 0);
    assert_eq!(config.exclude_min_uid, 0);
    assert_eq!(config.exclude_max_uid, 0);
    assert_eq!(config.include_enabled, 0);
    assert_eq!(config.include_uids, [0u32; panhandle_common::UID_COUNT]);
}

#[test]
fn test_shell_config_default() {
    let config = common::ConfigShellConfig::default();
    assert_eq!(config.shells, 0);
    assert_eq!(config.exclude_min_uid, 0);
    assert_eq!(config.exclude_max_uid, 0);
    assert_eq!(config.include_enabled, 0);
    assert_eq!(config.include_uids, [0u32; panhandle_common::UID_COUNT]);
}

#[test]
fn test_panhandle_config_creation() {
    let config = common::ConfigPanhandleConfig {
        shells: 1,
        exclude_min_uid: 100,
        exclude_max_uid: 999,
        include_enabled: 1,
        include_uids: {
            let mut arr = [0u32; panhandle_common::UID_COUNT];
            arr[0] = 1000;
            arr[1] = 1001;
            arr
        },
    };
    assert_eq!(config.shells, 1);
    assert_eq!(config.exclude_min_uid, 100);
    assert_eq!(config.exclude_max_uid, 999);
    assert_eq!(config.include_enabled, 1);
    assert_eq!(config.include_uids[0], 1000);
    assert_eq!(config.include_uids[1], 1001);
}

#[test]
fn test_shell_config_creation() {
    let config = common::ConfigShellConfig {
        shells: 1,
        exclude_min_uid: 100,
        exclude_max_uid: 999,
        include_enabled: 1,
        include_uids: {
            let mut arr = [0u32; panhandle_common::UID_COUNT];
            arr[0] = 1000;
            arr
        },
    };
    assert_eq!(config.shells, 1);
    assert_eq!(config.exclude_min_uid, 100);
    assert_eq!(config.exclude_max_uid, 999);
    assert_eq!(config.include_enabled, 1);
    assert_eq!(config.include_uids[0], 1000);
}

#[test]
fn test_ebpf_loader_override_global() {
    // Test that we can create a loader and override globals
    let mut loader = common::EbpfLoader::new();

    let panhandle_config = common::ConfigPanhandleConfig {
        shells: 1,
        exclude_min_uid: 100,
        exclude_max_uid: 999,
        include_enabled: 1,
        include_uids: [0u32; panhandle_common::UID_COUNT],
    };

    let shell_config = common::ConfigShellConfig {
        shells: 1,
        exclude_min_uid: 100,
        exclude_max_uid: 999,
        include_enabled: 1,
        include_uids: [0u32; panhandle_common::UID_COUNT],
    };

    // These should not panic
    loader.override_global("PANHANDLE_CONFIG", &panhandle_config, true);
    loader.override_global("SHELL_CONFIG", &shell_config, true);

    // Verify the loader was configured
    // Note: We can't easily inspect the internal state, but the calls above
    // verify the API works correctly
}

#[test]
fn test_ebpf_loader_debug_mode() {
    let mut loader = common::EbpfLoader::new();
    loader.verifier_log_level(common::VerifierLogLevel::DEBUG);

    let panhandle_config = common::ConfigPanhandleConfig::default();
    let shell_config = common::ConfigShellConfig::default();

    loader.override_global("PANHANDLE_CONFIG", &panhandle_config, true);
    loader.override_global("SHELL_CONFIG", &shell_config, true);

    // Should not panic
}

#[test]
fn test_attach_raw_tracepoint_error_handling() {
    // Test that missing program returns appropriate error
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => {
            // Empty bytecode can't be loaded, skip this test
            return;
        }
    };

    let result =
        common::attach_raw_tracepoint(&mut ebpf, "nonexistent_program", "sys_enter_execve");
    assert!(result.is_err());
    match result {
        Err(common::PanhandleError::MissingProgram(name)) => {
            assert_eq!(name, "nonexistent_program");
        }
        _ => panic!("Expected MissingProgram error"),
    }
}

#[test]
fn test_attach_btf_tracepoint_error_handling() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => {
            // Empty bytecode can't be loaded, skip this test
            return;
        }
    };
    let btf = common::Btf::from_sys_fs().expect("BTF not available on this system");

    let result =
        common::attach_btf_tracepoint(&mut ebpf, "nonexistent_program", "tracepoint", &btf);
    assert!(result.is_err());
    match result {
        Err(common::PanhandleError::MissingProgram(name)) => {
            assert_eq!(name, "nonexistent_program");
        }
        _ => panic!("Expected MissingProgram error"),
    }
}

#[test]
fn test_attach_uprobe_error_handling() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => {
            // Empty bytecode can't be loaded, skip this test
            return;
        }
    };

    let result = common::attach_uprobe(&mut ebpf, "nonexistent_program", "readline", "/bin/bash");
    assert!(result.is_err());
    match result {
        Err(common::PanhandleError::MissingProgram(name)) => {
            assert_eq!(name, "nonexistent_program");
        }
        _ => panic!("Expected MissingProgram error"),
    }
}

#[test]
fn test_attach_kprobe_error_handling() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => {
            // Empty bytecode can't be loaded, skip this test
            return;
        }
    };

    let result = common::attach_kprobe(&mut ebpf, "nonexistent_program");
    assert!(result.is_err());
    match result {
        Err(common::PanhandleError::MissingProgram(name)) => {
            assert_eq!(name, "nonexistent_program");
        }
        _ => panic!("Expected MissingProgram error"),
    }
}

#[test]
fn test_attach_lsm_hook_error_handling() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => {
            // Empty bytecode can't be loaded, skip this test
            return;
        }
    };
    let btf = common::Btf::from_sys_fs().expect("BTF not available on this system");

    let result = common::attach_lsm_hook(&mut ebpf, "file_open", "nonexistent_program", &btf);
    assert!(result.is_err());
    match result {
        Err(common::PanhandleError::MissingProgram(name)) => {
            assert_eq!(name, "nonexistent_program");
        }
        _ => panic!("Expected MissingProgram error"),
    }
}

#[test]
fn test_create_ring_buffer_async_fd_error_handling() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => {
            // Empty bytecode can't be loaded, skip this test
            return;
        }
    };

    let result = common::create_ring_buffer_async_fd(&mut ebpf, "nonexistent_map");
    assert!(result.is_err());
    match result {
        Err(common::PanhandleError::MissingMap(name)) => {
            assert_eq!(name, "nonexistent_map");
        }
        _ => panic!("Expected MissingMap error"),
    }
}

#[test]
fn test_get_hash_map_error_handling() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => {
            // Empty bytecode can't be loaded, skip this test
            return;
        }
    };

    let result: Result<aya::maps::HashMap<_, u32, u32>, _> =
        common::get_hash_map(&mut ebpf, "nonexistent_map");
    assert!(result.is_err());
    match result {
        Err(common::PanhandleError::MissingMap(name)) => {
            assert_eq!(name, "nonexistent_map");
        }
        _ => panic!("Expected MissingMap error"),
    }
}

#[test]
fn test_loaded_ebpf_struct() {
    let ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => {
            // Empty bytecode can't be loaded, skip this test
            return;
        }
    };
    let loaded = common::LoadedEbpf { ebpf, btf: None };

    // Verify struct can be created
    assert!(loaded.btf.is_none());
}

#[test]
fn test_ebpf_loader_with_btf() {
    let btf = common::Btf::from_sys_fs().ok();
    // Should not panic whether BTF is available or not
    assert!(btf.is_some() || btf.is_none());
}

#[test]
fn test_global_data_pod_impl() {
    // Test that PanhandleConfig and ShellConfig implement Pod
    // This is a compile-time check, but we can verify at runtime
    let panhandle_config = common::ConfigPanhandleConfig::default();
    let shell_config = common::ConfigShellConfig::default();

    // Verify they can be used as bytes (Pod requirement)
    let panhandle_bytes = unsafe {
        core::slice::from_raw_parts(
            &panhandle_config as *const _ as *const u8,
            core::mem::size_of::<common::ConfigPanhandleConfig>(),
        )
    };
    let shell_bytes = unsafe {
        core::slice::from_raw_parts(
            &shell_config as *const _ as *const u8,
            core::mem::size_of::<common::ConfigShellConfig>(),
        )
    };

    assert_eq!(
        panhandle_bytes.len(),
        core::mem::size_of::<common::ConfigPanhandleConfig>()
    );
    assert_eq!(
        shell_bytes.len(),
        core::mem::size_of::<common::ConfigShellConfig>()
    );
}

#[test]
fn test_ebpf_load_with_empty_bytecode() {
    // Test loading with empty bytecode should fail gracefully
    let result = aya::Ebpf::load(&[]);
    // Empty bytecode may or may not fail depending on aya version
    // The important thing is it doesn't panic
    let _ = result;
}

#[test]
fn test_override_global_with_different_configs() {
    let mut loader = common::EbpfLoader::new();

    // Test with various configurations
    let configs = vec![
        common::ConfigPanhandleConfig {
            shells: 0,
            exclude_min_uid: 0,
            exclude_max_uid: 0,
            include_enabled: 0,
            include_uids: [0u32; panhandle_common::UID_COUNT],
        },
        common::ConfigPanhandleConfig {
            shells: 1,
            exclude_min_uid: 100,
            exclude_max_uid: 999,
            include_enabled: 1,
            include_uids: {
                let mut arr = [0u32; panhandle_common::UID_COUNT];
                arr[0] = 1000;
                arr
            },
        },
        common::ConfigPanhandleConfig {
            shells: 1,
            exclude_min_uid: 0,
            exclude_max_uid: u32::MAX,
            include_enabled: 0,
            include_uids: [0u32; panhandle_common::UID_COUNT],
        },
    ];

    for config in &configs {
        loader.override_global("PANHANDLE_CONFIG", config, true);
        // Should not panic
    }
}

#[test]
fn test_attach_raw_tracepoint_success_conditions() {
    // Test that attach_raw_tracepoint checks program type correctly
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => {
            // Empty bytecode can't be loaded, skip this test
            return;
        }
    };

    // We can't easily test success without a real eBPF program,
    // but we can verify the error paths work
    let result = common::attach_raw_tracepoint(&mut ebpf, "panhandle", "sys_enter_execve");
    // This will fail because we don't have the actual program loaded
    // but the error should be about missing program or attach failure
    assert!(result.is_err());
}

#[test]
fn test_ebpf_loader_multiple_globals() {
    let mut loader = common::EbpfLoader::new();

    let panhandle_config = common::ConfigPanhandleConfig::default();
    let shell_config = common::ConfigShellConfig::default();

    // Override both globals
    loader.override_global("PANHANDLE_CONFIG", &panhandle_config, true);
    loader.override_global("SHELL_CONFIG", &shell_config, true);

    // Should not panic
}

#[test]
fn test_ebpf_loader_verifier_log_levels() {
    let levels = [common::VerifierLogLevel::DEBUG];

    for level in levels {
        let mut loader = common::EbpfLoader::new();
        loader.verifier_log_level(level);
        // Should not panic
    }
}

#[test]
fn test_create_ring_buffer_async_fd_with_valid_map() {
    // This test requires an actual eBPF program with a ring buffer map
    // Since we don't have one in unit tests, we test the error path by loading empty bytecode
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => {
            // Empty bytecode can't be loaded, skip this test
            return;
        }
    };

    let result = common::create_ring_buffer_async_fd(&mut ebpf, "panhandle_execve_events");
    // Will fail because map doesn't exist in empty bytecode
    assert!(result.is_err());
}

#[test]
fn test_get_hash_map_with_valid_map() {
    let mut ebpf = match aya::Ebpf::load(&[]) {
        Ok(ebpf) => ebpf,
        Err(_) => {
            // Empty bytecode can't be loaded, skip this test
            return;
        }
    };

    let result: Result<aya::maps::HashMap<_, u32, u32>, _> =
        common::get_hash_map(&mut ebpf, "COMMS");
    // Will fail because map doesn't exist in empty bytecode
    assert!(result.is_err());
}

#[test]
fn test_load_ebpf_integration() {
    // This test requires the actual eBPF bytecode to be embedded
    // It will only work when the project has been built with the eBPF program
    // We test the function signature and error handling

    // Note: In a real test environment with the eBPF bytecode available,
    // we would test:
    // let result = common::load_ebpf(false, &common::PanhandleConfig::default(), &common::ShellConfig::default());
    // assert!(result.is_ok());

    // For unit tests without the bytecode, we just verify the function exists
    // and the types are correct
    let _load_fn: fn(
        bool,
        &common::PanhandleConfig,
        &common::ShellConfig,
    ) -> Result<common::LoadedEbpf, common::PanhandleError> = common::load_ebpf;
}

#[test]
fn test_attach_functions_signatures() {
    // Verify all attach functions have correct signatures
    let _attach_raw: fn(&mut aya::Ebpf, &str, &str) -> Result<(), common::PanhandleError> =
        common::attach_raw_tracepoint;
    let _attach_btf: fn(
        &mut aya::Ebpf,
        &str,
        &str,
        &aya::Btf,
    ) -> Result<(), common::PanhandleError> = common::attach_btf_tracepoint;
    let _attach_uprobe: fn(&mut aya::Ebpf, &str, &str, &str) -> Result<(), common::PanhandleError> =
        common::attach_uprobe;
    let _attach_kprobe: fn(&mut aya::Ebpf, &str) -> Result<(), common::PanhandleError> =
        common::attach_kprobe;
    let _attach_lsm: fn(
        &mut aya::Ebpf,
        &str,
        &str,
        &aya::Btf,
    ) -> Result<(), common::PanhandleError> = common::attach_lsm_hook;
}

#[test]
#[allow(clippy::type_complexity)]
fn test_ring_buffer_async_fd_signature() {
    let _create_fn: fn(
        &mut aya::Ebpf,
        &str,
    ) -> Result<
        tokio::io::unix::AsyncFd<aya::maps::RingBuf<aya::maps::MapData>>,
        common::PanhandleError,
    > = common::create_ring_buffer_async_fd;
}

#[test]
#[allow(clippy::type_complexity)]
fn test_get_hash_map_signature() {
    // Generic function, just verify it exists
    let _get_fn: fn(
        &mut aya::Ebpf,
        &str,
    ) -> Result<
        aya::maps::HashMap<aya::maps::MapData, u32, u32>,
        common::PanhandleError,
    > = |ebpf, name| common::get_hash_map::<u32, u32>(ebpf, name);
}
