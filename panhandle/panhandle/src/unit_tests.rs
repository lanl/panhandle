#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{helpers::*, input_configs::*, monitor_cpu_usage::*};

    // test that valid config files are being loaded correctly into the ConfigArgs struct
    #[tokio::test]
    async fn test_load_config_args_valid() {
        // test when all bools are turned on
        let expected_all_bools = ConfigArgs {
            bash: true,
            debug: true,
            syscall_execve: true,
            json: true,
            verbose: true,
            zsh: true,
            quiet: true,
            shells: true,
            socket: true,
            io: true,
            cpu: true,
            gpu: true,
            memory: true,
            ..Default::default()
        };

        let all_bools_yaml = String::from("../../test-configs/all-bools.yaml");
        let all_bools_json = String::from("../../test-configs/all-bools.json");

        // assert that config loaded all bools correctly
        assert_eq!(
            Ok(expected_all_bools.clone()),
            load_config_args(all_bools_yaml).await
        );
        assert_eq!(
            Ok(expected_all_bools),
            load_config_args(all_bools_json).await
        );

        // test the default config
        let expected_default = ConfigArgs {
            shells: true,
            syscall_execve: true,
            exclude_min_uid: Some(0),
            json: true,
            output: Some(vec![
                OutputConfig::File {
                    file: PathBuf::from("/var/log/panhandle/panhandle.log"),
                },
                OutputConfig::Syslog {
                    syslog: Some(Some("hpcsyslog.lanl.gov:514/tcp".to_string())),
                },
            ]),
            ..Default::default()
        };

        let default_yaml = String::from("../../test-configs/default.yaml");
        let default_json = String::from("../../test-configs/default.json");

        // assert that config loaded defaults correctly
        assert_eq!(
            Ok(expected_default.clone()),
            load_config_args(default_yaml).await
        );
        assert_eq!(Ok(expected_default), load_config_args(default_json).await);

        // test all non_bool fields get loaded correctly
        let expected_non_bools = ConfigArgs {
            verbose: true,
            exclude_min_uid: Some(0),
            exclude_max_uid: Some(23),
            memory_faults: Some(100),
            executables: Some(vec![
                String::from("/path1/user1"),
                String::from("/path2/something/files"),
                String::from("/path3/somewhere"),
            ]),
            pid_list: Some(vec![1, 2, 3]),
            include_uid: Some(vec![String::from("uid1")]),
            output: Some(vec![OutputConfig::Syslog {
                syslog: Some(Some("hpcsyslog.lanl.gov:514/tcp".to_string())),
            }]),
            ..Default::default()
        };

        let non_bools_yaml = String::from("../../test-configs/non-bools.yaml");
        let non_bools_json = String::from("../../test-configs/non-bools.json");

        // assert that config loaded non_bools correctly
        assert_eq!(
            Ok(expected_non_bools.clone()),
            load_config_args(non_bools_yaml).await
        );
        assert_eq!(
            Ok(expected_non_bools),
            load_config_args(non_bools_json).await
        );
    }

    // test that invalid config files receive the correct errors
    #[tokio::test]
    async fn test_load_config_args_invalid() {
        // test file not found error
        let nonexistent_file = "nonexistent.yaml";
        let expected_error = Err(format!("Config file not found: {}", nonexistent_file));
        assert_eq!(
            expected_error,
            load_config_args(nonexistent_file.to_string()).await
        );

        // test invalid json error
        let invalid_json = "../../test-configs/invalid.json";
        let expected_error = "Invalid JSON config";
        match load_config_args(invalid_json.to_string()).await {
            Ok(_) => panic!("load_config_args should not return Ok for invalid JSON"),
            Err(returned_error) => assert!(returned_error.contains(expected_error)),
        }

        // test invalid yaml error
        let invalid_yaml = "../../test-configs/invalid.yaml";
        let expected_error = "Invalid YAML config";
        match load_config_args(invalid_yaml.to_string()).await {
            Ok(_) => panic!("load_config_args should not return Ok for invalid YAML"),
            Err(returned_error) => assert!(returned_error.contains(expected_error)),
        }

        // test unsupported config error
        let xml_file = "../../test-configs/invalid.xml";
        let expected_error = "Unsupported config type";
        match load_config_args(xml_file.to_string()).await {
            Ok(_) => {
                panic!("load_config_args should not return Ok for unsupported config extension")
            }
            Err(returned_error) => assert!(returned_error.contains(expected_error)),
        }
    }

    // test that two valid ConfigArgs and RawArgs structs are merged correctly according to the logic that cli args should overwrite config args
    #[tokio::test]
    async fn test_merge_args_valid() {
        // Make sure that config bools come through as true even when no cli is provided
        let config = ConfigArgs {
            bash: true,
            debug: true,
            syscall_execve: true,
            json: true,
            verbose: true,
            zsh: true,
            quiet: true,
            shells: true,
            ..Default::default()
        };

        // equivalent to no cli arguments being provided
        let cli = RawArgs {
            ..Default::default()
        };

        // expected args after merging config and empty cli
        let expected_merged_args = RawArgs {
            bash: true,
            debug: true,
            syscall_execve: true,
            json: true,
            verbose: true,
            zsh: true,
            quiet: true,
            shells: true,
            ..Default::default()
        };

        assert_eq!(expected_merged_args, merge_args(cli, config).await);

        // General test for more complex merge logic, output/syslog should be overwritten, output/file should persist, bash should be true as specified in cli
        let config = ConfigArgs {
            shells: true,
            syscall_execve: true,
            exclude_min_uid: Some(0),
            json: true,
            output: Some(vec![
                OutputConfig::File {
                    file: PathBuf::from("/var/log/panhandle/panhandle.log"),
                },
                OutputConfig::Syslog {
                    syslog: Some(Some("hpcsyslog.lanl.gov:514/tcp".to_string())),
                },
            ]),
            ..Default::default()
        };

        // overwrite syslog option to be "unix", this assumes user wants to keep file option the same, so they did not mention it in cli
        let cli = RawArgs {
            bash: true,
            output: Some(OutputCommand::Output {
                file: None,
                http: None,
                syslog: Some(Some("unix".to_string())),
            }),
            ..Default::default()
        };

        // bash was specified in cli, so it should be true, while others specified in config should remain true
        // file was not respecified, so its config version should persist
        // syslog was respecified, so its value should go from "hpcsyslog.lanl.gov:514/tcp"->"unix"
        let expected = RawArgs {
            bash: true,
            shells: true,
            syscall_execve: true,
            exclude_min_uid: Some(0),
            json: true,
            output: Some(OutputCommand::Output {
                file: Some(PathBuf::from("/var/log/panhandle/panhandle.log")),
                http: None,
                syslog: Some(Some("unix".to_string())),
            }),
            ..Default::default()
        };

        assert_eq!(expected, merge_args(cli, config).await);
    }

    // test that valid syslog addresses return as Ok
    #[tokio::test]
    async fn test_syslog_valid() {
        let valid_addr_tcp = "hpcsyslog.lanl.gov:514/tcp";
        let valid_addr_udp = "hpcsyslog.lanl.gov:514/udp";
        let valid_local1 = "unix";
        let valid_local2 = "/dev/log";

        assert!(validate_syslog(valid_addr_tcp).await.is_ok());
        assert!(validate_syslog(valid_addr_udp).await.is_ok());
        assert!(validate_syslog(valid_local1).await.is_ok());
        assert!(validate_syslog(valid_local2).await.is_ok());
    }

    // test that invalid syslog arguments receive the correct errors
    #[tokio::test]
    async fn test_syslog_invalid() {
        // test that an invalid hostname returns the correct error
        let addr_invalid_hostname = "invalid_host.lanl.gov:514/tcp";
        let expected_invalid_hostname = Err("\nSYSLOG: Invalid remote address hostname provided. \
                        \nBe sure to enter in the format: --syslog <hostname>:<port>/tcp or /udp"
            .to_string());
        assert_eq!(
            expected_invalid_hostname,
            validate_syslog(addr_invalid_hostname).await
        );

        // test that an invalid TCP port number returns the correct error
        let addr_invalid_port = "hpcsyslog.lanl.gov:214/tcp";
        let expected_invalid_port = Err("\nSYSLOG: Provided TCP port number is not reachable. \
                        \nBe sure to enter in the format: --syslog <hostname>:<port>/tcp or /udp"
            .to_string());
        assert_eq!(
            expected_invalid_port,
            validate_syslog(addr_invalid_port).await
        );

        // test general syslog error
        let addr_invalid_general = "something_invalid/tc";
        let expected_invalid_general = Err(format!(
            "\nSYSLOG: Invalid syslog argument '{}' provided. \
            \nUSAGE:\n  Local syslog message output: --syslog /dev/log or --syslog unix or --syslog \
            \n  Remote syslog message output: --syslog <hostname>:<port>/tcp or /udp",
            addr_invalid_general
        ));
        assert_eq!(
            expected_invalid_general,
            validate_syslog(addr_invalid_general).await
        );
    }

    // test that a valid url receives an Ok
    #[tokio::test]
    async fn test_url_valid() {
        let url_valid = "http://localhost:4319/raw-audit";
        assert!(validate_url(url_valid).await.is_ok());
    }

    // test that an invalid url receives an error
    #[tokio::test]
    async fn test_url_invalid() {
        let url_invalid = "www.invalid.com";
        assert!(validate_url(url_invalid).await.is_err());
    }

    // test that output_needs correctly determines which of plain_string/json_string
    // output_message will actually use, for every meaningfully distinct combination of
    // output channel flags
    #[test]
    fn test_output_needs() {
        // no output channels, no debug: only the plain terminal log is used
        assert_eq!(output_needs(false, false, false, false), (true, false));
        // no output channels, debug on: the terminal log always uses the json form when debug
        assert_eq!(output_needs(false, false, false, true), (false, true));
        // http on, non-json: http uses plain, terminal (non-debug) uses plain
        assert_eq!(output_needs(true, false, false, false), (true, false));
        // http on, json requested: http uses json, terminal (non-debug) still uses plain
        assert_eq!(output_needs(true, false, true, false), (true, true));
        // http on, json requested, debug on: plain is unused by either channel now
        assert_eq!(output_needs(true, false, true, true), (false, true));
        // syslog behaves the same as http for channel selection
        assert_eq!(output_needs(false, true, false, false), (true, false));
        // json_output with no channel enabled has no effect: terminal (non-debug) still
        // only needs plain, and nothing needs json
        assert_eq!(output_needs(false, false, true, false), (true, false));
        // json_output with no channel enabled but debug on: only the debug terminal path
        // needs json
        assert_eq!(output_needs(false, false, true, true), (false, true));
    }

    // test that read_ring_item correctly reconstructs a POD struct from its raw bytes,
    // the same way it reconstructs Readline/ExecveEvent from a ring buffer item
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
        // SAFETY: reinterpreting a repr(C) Copy struct as its own raw bytes for the test
        let bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(
                &original as *const TestEvent as *const u8,
                core::mem::size_of::<TestEvent>(),
            )
        };

        // SAFETY: bytes was constructed directly from a TestEvent of the same size above
        let reconstructed: TestEvent = unsafe { read_ring_item(bytes) };
        assert_eq!(original, reconstructed);
    }

    // ring buffer items can be larger than size_of::<T>() (e.g. alignment padding); the
    // struct should be read from the front regardless of trailing bytes
    #[test]
    fn test_read_ring_item_ignores_trailing_bytes() {
        #[repr(C)]
        #[derive(Copy, Clone, PartialEq, Debug)]
        struct TestEvent {
            a: u32,
        }

        let original = TestEvent { a: 7 };
        // SAFETY: reinterpreting a repr(C) Copy struct as its own raw bytes for the test
        let mut bytes: Vec<u8> = unsafe {
            core::slice::from_raw_parts(
                &original as *const TestEvent as *const u8,
                core::mem::size_of::<TestEvent>(),
            )
        }
        .to_vec();
        bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);

        // SAFETY: bytes starts with a valid TestEvent's bytes, followed by extra padding
        let reconstructed: TestEvent = unsafe { read_ring_item(&bytes) };
        assert_eq!(original, reconstructed);
    }

    // test the per-PID CPU% formula: 100% = one core fully busy for the whole interval
    #[test]
    fn test_calc_cpu_percent() {
        assert_eq!(calc_cpu_percent(1_000_000_000, 1_000_000_000), 100.0);
        assert_eq!(calc_cpu_percent(500_000_000, 1_000_000_000), 50.0);
        assert_eq!(calc_cpu_percent(0, 1_000_000_000), 0.0);
        // multi-threaded processes can exceed 100% (200% = fully using two cores)
        assert_eq!(calc_cpu_percent(2_000_000_000, 1_000_000_000), 200.0);
        // a zero interval must not divide-by-zero or panic
        assert_eq!(calc_cpu_percent(1_000_000_000, 0), 0.0);
    }

    // test the system-wide CPU% formula: normalized 0-100% across all cores
    #[test]
    fn test_calc_system_cpu_percent() {
        // 1 of 4 cores fully busy for the whole interval => 25%
        assert_eq!(
            calc_system_cpu_percent(1_000_000_000, 1_000_000_000, 4),
            25.0
        );
        // all 4 cores fully busy => 100%
        assert_eq!(
            calc_system_cpu_percent(4_000_000_000, 1_000_000_000, 4),
            100.0
        );
        // idle system => 0%
        assert_eq!(calc_system_cpu_percent(0, 1_000_000_000, 4), 0.0);
        // clamped at 100% even if timing jitter pushes the raw ratio slightly over
        assert_eq!(
            calc_system_cpu_percent(5_000_000_000, 1_000_000_000, 4),
            100.0
        );
        // a zero interval or zero cpu count must not divide-by-zero or panic
        assert_eq!(calc_system_cpu_percent(1_000_000_000, 0, 4), 0.0);
        assert_eq!(
            calc_system_cpu_percent(1_000_000_000, 1_000_000_000, 0),
            0.0
        );
    }
}
