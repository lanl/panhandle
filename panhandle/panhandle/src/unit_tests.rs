#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use clap::Parser;

    use crate::{
        helpers::*, input_configs::*, monitor_cpu_usage::*, monitor_gpu_usage::*,
        monitor_io_usage::*, monitor_network_usage::*, procfs_helpers::*,
    };
    use panhandle_common::*;

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

    // test config files at the edges of what serde will accept: an empty file, a file
    // with unknown fields (ConfigArgs uses deny_unknown_fields), and a partial config
    // where unset fields fall back to their defaults
    #[tokio::test]
    async fn test_load_config_args_edge_cases() {
        // an empty config file parses as an empty document and yields all defaults,
        // consistent with how unset fields fall back to their defaults
        let empty_yaml = "../../test-configs/empty.yaml";
        assert_eq!(
            Ok(ConfigArgs::default()),
            load_config_args(empty_yaml.to_string()).await
        );

        // a config file with a field ConfigArgs doesn't declare must be rejected
        let unknown_yaml = "../../test-configs/unknown-field.yaml";
        match load_config_args(unknown_yaml.to_string()).await {
            Ok(_) => panic!("load_config_args should not return Ok for an unknown config field"),
            Err(returned_error) => assert!(
                returned_error.contains("Invalid YAML config"),
                "unexpected error: {}",
                returned_error
            ),
        }

        // a partial config only sets what it declares; everything else keeps defaults
        let partial_json = "../../test-configs/partial.json";
        let expected = ConfigArgs {
            verbose: true,
            exclude_min_uid: Some(1000),
            ..Default::default()
        };
        assert_eq!(
            Ok(expected),
            load_config_args(partial_json.to_string()).await
        );
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

    // test that valid syslog addresses return as Ok. Uses "localhost" plus a locally
    // bound ephemeral port rather than any real remote syslog server, so this doesn't
    // depend on LANL-internal infrastructure (or any network access at all) being
    // reachable from wherever the test suite runs.
    #[tokio::test]
    async fn test_syslog_valid() {
        // kept alive for the duration of the test so the TCP-reachability check below
        // has something real to connect to
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let valid_addr_tcp = format!("localhost:{port}/tcp");
        // UDP is connectionless, so validate_syslog never actually probes reachability
        // for it -- only DNS resolution of the hostname matters, so no listener is
        // needed here
        let valid_addr_udp = "localhost:9/udp";
        let valid_local1 = "unix";
        let valid_local2 = "/dev/log";

        assert!(validate_syslog(&valid_addr_tcp).await.is_ok());
        assert!(validate_syslog(valid_addr_udp).await.is_ok());
        assert!(validate_syslog(valid_local1).await.is_ok());
        assert!(validate_syslog(valid_local2).await.is_ok());

        drop(listener);
    }

    // test that invalid syslog arguments receive the correct errors. Like
    // test_syslog_valid, this avoids depending on any real remote host.
    #[tokio::test]
    async fn test_syslog_invalid() {
        // test that an invalid hostname returns the correct error. ".invalid" is a
        // reserved TLD (RFC 2606) guaranteed to never resolve, so this doesn't depend
        // on any specific DNS zone's current (and potentially changing) behavior.
        let addr_invalid_hostname = "nonexistent-host.invalid:514/tcp";
        let expected_invalid_hostname = Err("\nSYSLOG: Invalid remote address hostname provided. \
                        \nBe sure to enter in the format: --syslog <hostname>:<port>/tcp or /udp"
            .to_string());
        assert_eq!(
            expected_invalid_hostname,
            validate_syslog(addr_invalid_hostname).await
        );

        // test that an unreachable TCP port returns the correct error. Bind then
        // immediately release a local ephemeral port so it's guaranteed nothing is
        // listening there, rather than depending on a specific remote host/port
        // happening to reject connections.
        let closed_port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        }; // listener dropped here, so the port is no longer bound
        let addr_invalid_port = format!("localhost:{closed_port}/tcp");
        let expected_invalid_port = Err("\nSYSLOG: Provided TCP port number is not reachable. \
                        \nBe sure to enter in the format: --syslog <hostname>:<port>/tcp or /udp"
            .to_string());
        assert_eq!(
            expected_invalid_port,
            validate_syslog(&addr_invalid_port).await
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

    // test the url validation edge cases: schemes other than http, empty input,
    // scheme-less input, and a missing host all behave as expected
    #[tokio::test]
    async fn test_url_edge_cases() {
        // https is accepted alongside http
        assert!(validate_url("https://example.com").await.is_ok());
        // any syntactically valid scheme passes; validation is syntax-only
        assert!(validate_url("ftp://example.com").await.is_ok());
        // empty input is rejected
        assert!(validate_url("").await.is_err());
        // a scheme-less hostname is not a valid absolute URL
        assert!(validate_url("example.com").await.is_err());
        // "http://" has no host component
        assert!(validate_url("http://").await.is_err());
        // a protocol-relative URL is not absolute either
        assert!(validate_url("//example.com/path").await.is_err());
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
        // http on, json requested: http and the terminal (non-debug) both use json
        assert_eq!(output_needs(true, false, true, false), (false, true));
        // http on, json requested, debug on: plain is unused by either channel now
        assert_eq!(output_needs(true, false, true, true), (false, true));
        // syslog behaves the same as http for channel selection
        assert_eq!(output_needs(false, true, false, false), (true, false));
        // json_output with no channel enabled: the terminal (non-debug) now needs json,
        // since --json applies to the terminal log as well
        assert_eq!(output_needs(false, false, true, false), (false, true));
        // json_output with no channel enabled but debug on: only the debug terminal path
        // needs json
        assert_eq!(output_needs(false, false, true, true), (false, true));
    }

    // test that output_message with neither http nor syslog enabled never touches the
    // network -- it only falls through to the terminal logging branch and returns
    #[tokio::test]
    async fn test_output_message_no_channels_noop() {
        let client = reqwest::Client::new();
        let hostname = Arc::new("node1".to_string());
        let syslog_address = Arc::new(String::new());
        let global_url = Arc::new(String::new());
        let plain = "plain text".to_string();
        let json = "{\"a\":1}".to_string();

        output_message(
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
        output_message(
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

    // test that send_http_post rejects a syntactically invalid URL without ever
    // attempting a connection (reqwest fails at request build time)
    #[tokio::test]
    async fn test_send_http_post_invalid_url_errors() {
        let client = reqwest::Client::new();
        let url = Arc::new("not a url".to_string());
        let body = Arc::new("payload".to_string());

        assert!(
            send_http_post(&client, &url, &body, &false, &false)
                .await
                .is_err()
        );
    }

    // test that send_syslog delivers a plaintext message over UDP to a loopback listener
    // -- the full round trip through the syslog formatter and writer
    #[tokio::test]
    async fn test_send_syslog_udp_loopback() {
        use std::net::UdpSocket;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind loopback UDP socket");
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("set read timeout");
        let port = socket.local_addr().expect("local addr").port();
        let syslog_address = Arc::new(format!("127.0.0.1:{}/udp", port));
        let message = Arc::new("panhandle udp test message".to_string());
        let hostname = "testhost".to_string();

        let result = send_syslog(&hostname, &message, &syslog_address, &false, &false).await;
        assert!(result.is_ok());

        let mut buf = [0u8; 2048];
        let (len, _src) = socket.recv_from(&mut buf).expect("receive syslog datagram");
        let received = String::from_utf8_lossy(&buf[..len]);
        assert!(
            received.contains("panhandle udp test message"),
            "syslog datagram should carry the message, got: {received}"
        );
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

    // test that calc_delta distinguishes "never observed this value before" from
    // "previously observed as exactly 0", so the first sample after monitoring starts
    // doesn't report a delta spanning the process/system's entire lifetime
    #[test]
    fn test_calc_delta() {
        // no prior observation: must not compute a delta against an implicit 0 baseline
        assert_eq!(calc_delta(1_000_000_000, None), 0);
        assert_eq!(calc_delta(0, None), 0);
        // normal case: delta against a real prior observation
        assert_eq!(calc_delta(100, Some(40)), 60);
        // no change since last observation
        assert_eq!(calc_delta(50, Some(50)), 0);
        // counter went backwards (e.g. PID reuse observed a lower value): saturates to 0
        // rather than underflowing
        assert_eq!(calc_delta(100, Some(150)), 0);
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

    // test which conditions activate the default execve monitor: explicit request, or
    // fallback when no other monitoring flag was given at all
    #[test]
    fn test_should_run_default_execve_monitor() {
        // local helper so the test can still express cases as a RawArgs, even though the
        // function itself takes individual fields (see its doc comment for why)
        fn check(args: &RawArgs) -> bool {
            should_run_default_execve_monitor(
                args.syscall_execve,
                args.bash,
                args.zsh,
                args.memory_faults.is_some(),
                args.socket,
                args.memory,
                args.cpu,
                args.gpu,
                args.io,
                args.syscalls.is_some(),
            )
        }

        // explicitly requested: always runs, regardless of what else is set
        let args = RawArgs {
            syscall_execve: true,
            cpu: true,
            ..Default::default()
        };
        assert!(check(&args));

        // nothing else selected: runs as the fallback default
        assert!(check(&RawArgs::default()));

        // any other monitoring flag selected: the default execve monitor does not run
        let args = RawArgs {
            cpu: true,
            ..Default::default()
        };
        assert!(!check(&args));

        let args = RawArgs {
            bash: true,
            ..Default::default()
        };
        assert!(!check(&args));

        let args = RawArgs {
            zsh: true,
            ..Default::default()
        };
        assert!(!check(&args));

        let args = RawArgs {
            memory_faults: Some(1),
            ..Default::default()
        };
        assert!(!check(&args));

        let args = RawArgs {
            socket: true,
            ..Default::default()
        };
        assert!(!check(&args));

        let args = RawArgs {
            memory: true,
            ..Default::default()
        };
        assert!(!check(&args));

        let args = RawArgs {
            gpu: true,
            ..Default::default()
        };
        assert!(!check(&args));

        let args = RawArgs {
            io: true,
            ..Default::default()
        };
        assert!(!check(&args));

        let args = RawArgs {
            syscalls: Some(vec!["execve".to_string()]),
            ..Default::default()
        };
        assert!(!check(&args));
    }

    // test that RawArgs parses with sensible defaults when no flags are given
    #[test]
    fn test_raw_args_parse_defaults() {
        let args = RawArgs::try_parse_from(["panhandle"]).unwrap();
        assert!(!args.bash);
        assert!(!args.cpu);
        assert_eq!(args.poll, None);
        assert_eq!(args.executables, None);
    }

    // test that boolean flags and a value-taking option parse correctly together
    #[test]
    fn test_raw_args_parse_flags_and_value() {
        let args =
            RawArgs::try_parse_from(["panhandle", "--cpu", "--gpu", "--verbose", "--poll", "10"])
                .unwrap();
        assert!(args.cpu);
        assert!(args.gpu);
        assert!(args.verbose);
        assert_eq!(args.poll, Some(10));
    }

    // test that a comma-separated list option parses into the expected Vec
    #[test]
    fn test_raw_args_parse_comma_separated_list() {
        let args =
            RawArgs::try_parse_from(["panhandle", "--executables", "/bin/ls,/bin/cat,/bin/echo"])
                .unwrap();
        assert_eq!(
            args.executables,
            Some(vec![
                "/bin/ls".to_string(),
                "/bin/cat".to_string(),
                "/bin/echo".to_string()
            ])
        );
    }

    // test that the `output` subcommand and its --http/--syslog options parse correctly,
    // including a bare --syslog with no value
    #[test]
    fn test_raw_args_parse_output_subcommand() {
        let args = RawArgs::try_parse_from([
            "panhandle",
            "output",
            "--http",
            "http://localhost:8080",
            "--syslog",
        ])
        .unwrap();
        match args.output {
            Some(OutputCommand::Output { http, syslog, .. }) => {
                assert_eq!(http, Some("http://localhost:8080".to_string()));
                // bare --syslog with no value parses as Some(None)
                assert_eq!(syslog, Some(None));
            }
            None => panic!("expected an output subcommand to be parsed"),
        }
    }

    // test that --poll's value_parser range (1..) rejects 0 at parse time
    #[test]
    fn test_raw_args_parse_poll_rejects_zero() {
        assert!(RawArgs::try_parse_from(["panhandle", "--poll", "0"]).is_err());
    }

    // test that the typed value parsers reject malformed scalars at parse time rather
    // than deferring the failure to runtime
    #[test]
    fn test_raw_args_parse_invalid_scalars() {
        // a negative PID fails the u32 parse for --pid-list
        assert!(RawArgs::try_parse_from(["panhandle", "--pid-list", "-1"]).is_err());
        // a non-numeric UID fails the u32 parse for --exclude-min-uid
        assert!(RawArgs::try_parse_from(["panhandle", "--exclude-min-uid", "notanumber"]).is_err());
        // a negative memory-faults threshold fails the u64 parse
        assert!(RawArgs::try_parse_from(["panhandle", "--memory-faults", "-5"]).is_err());
    }

    // test that resolve_comm_list_mode picks the right mode for each list combination, and
    // errors when both --comm-deny and --comm-allow are provided rather than silently
    // preferring one
    #[test]
    fn test_resolve_comm_list_mode() {
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

        // an explicitly-provided but empty list still selects its mode with an empty
        // eBPF map payload: Some(vec![]) is not the same as None
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

        // both provided: must error rather than silently picking one
        assert!(resolve_comm_list_mode(&deny, &allow).is_err());
    }

    // test that an empty --executables list matches everything (the "monitor everything"
    // default), and that a populated one matches only its exact entries
    #[test]
    fn test_event_matches_executable_filter() {
        // no filter configured: every event is reported
        assert!(event_matches_executable_filter(&[], "/usr/bin/ssh"));
        assert!(event_matches_executable_filter(&[], ""));

        let filter = vec!["/usr/bin/ssh".to_string(), "/usr/bin/scp".to_string()];
        assert!(event_matches_executable_filter(&filter, "/usr/bin/ssh"));
        assert!(event_matches_executable_filter(&filter, "/usr/bin/scp"));
        assert!(!event_matches_executable_filter(&filter, "/usr/bin/ls"));
        // matching is exact, not prefix/substring based
        assert!(!event_matches_executable_filter(&filter, "/usr/bin"));
        assert!(!event_matches_executable_filter(&filter, "ssh"));
        assert!(!event_matches_executable_filter(&filter, ""));
    }

    // regression test: a batch drained from the ring buffer holds many unrelated events,
    // so a non-matching event must skip only itself. Previously the filter used `break`,
    // which abandoned every event queued behind the first non-match -- silently dropping
    // matching events whenever --executables was set. Mirrors the per-event filtering
    // loop in consume_shell_ebpf_map/consume_execve_ebpf_map, which can't be driven
    // directly from a test without a live eBPF ring buffer.
    #[test]
    fn test_executable_filter_skips_only_nonmatching_events() {
        let filter = vec!["/usr/bin/ssh".to_string()];
        // the non-matching event is deliberately first, ahead of two matching ones
        let batch = ["/usr/bin/ls", "/usr/bin/ssh", "/usr/bin/ssh"];

        let mut reported = Vec::new();
        for event in batch {
            if !event_matches_executable_filter(&filter, event) {
                continue;
            }
            reported.push(event);
        }

        assert_eq!(reported, vec!["/usr/bin/ssh", "/usr/bin/ssh"]);
    }

    // test the executable-count and uid-count limit checks at and past their boundary
    #[test]
    fn test_validate_count_executables() {
        assert!(validate_count(EXECUTABLE_COUNT, EXECUTABLE_COUNT, "executables").is_ok());
        assert!(validate_count(EXECUTABLE_COUNT + 1, EXECUTABLE_COUNT, "executables").is_err());
    }

    #[test]
    fn test_validate_count_uids() {
        assert!(validate_count(UID_COUNT, UID_COUNT, "UIDs").is_ok());
        assert!(validate_count(UID_COUNT + 1, UID_COUNT, "UIDs").is_err());
    }

    // test the same boundary against the process-blocking count limits, which main()
    // enforces at runtime (via validate_count) since clap can't reject an over-limit
    // comma-separated --block-paths/--comm-allow/--comm-deny list at parse time
    #[test]
    fn test_validate_count_block_paths() {
        assert!(
            validate_count(MAX_BLOCKED_PATHS, MAX_BLOCKED_PATHS, "block-paths entries").is_ok()
        );
        assert!(
            validate_count(
                MAX_BLOCKED_PATHS + 1,
                MAX_BLOCKED_PATHS,
                "block-paths entries"
            )
            .is_err()
        );
    }

    #[test]
    fn test_validate_count_comm_lists() {
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

    // test that the validate_count error message interpolates the label and the limit so
    // callers can tell which limit was exceeded
    #[test]
    fn test_validate_count_error_message() {
        let err =
            validate_count(EXECUTABLE_COUNT + 1, EXECUTABLE_COUNT, "executables").unwrap_err();
        assert_eq!(
            err,
            format!(
                "The number of executables requested to monitor exceeds the maximum of {}",
                EXECUTABLE_COUNT
            )
        );

        let err = validate_count(UID_COUNT + 1, UID_COUNT, "UIDs").unwrap_err();
        assert_eq!(
            err,
            format!(
                "The number of UIDs requested to monitor exceeds the maximum of {}",
                UID_COUNT
            )
        );
    }

    // test that get_canonical_executable_list keeps the original path, adds a distinct
    // canonical form when the input resolves through a symlink, and doesn't choke on a
    // nonexistent path
    #[test]
    fn test_get_canonical_executable_list() {
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

        // the originally-provided path is always kept, even after canonicalization
        assert!(result.contains(&symlink_path.to_string_lossy().to_string()));
        // a symlink resolves to an additional canonical entry pointing at the real file
        let canonical_real = std::fs::canonicalize(&real_file).unwrap();
        assert!(result.contains(&canonical_real.to_string_lossy().to_string()));
        // a nonexistent path yields no canonical form beyond itself
        assert!(result.contains(&nonexistent.to_string_lossy().to_string()));
        assert_eq!(result.len(), 3);

        // an empty input list yields an empty output list without panicking
        let empty_input: Vec<String> = Vec::new();
        assert!(get_canonical_executable_list(&empty_input).is_empty());

        std::fs::remove_dir_all(&base).ok();
    }

    // test that --syscalls, --memory-faults, --exclude-min-uid/--exclude-max-uid,
    // --pid-list, and --include-uid all parse into their expected typed values
    #[test]
    fn test_raw_args_parse_remaining_scalar_and_list_options() {
        let args = RawArgs::try_parse_from([
            "panhandle",
            "--syscalls",
            "openat,connect",
            "--memory-faults",
            "100",
            "--exclude-min-uid",
            "1",
            "--exclude-max-uid",
            "998",
            "--pid-list",
            "123,456",
            "--include-uid",
            "1000,1001",
        ])
        .unwrap();

        assert_eq!(
            args.syscalls,
            Some(vec!["openat".to_string(), "connect".to_string()])
        );
        assert_eq!(args.memory_faults, Some(100));
        assert_eq!(args.exclude_min_uid, Some(1));
        assert_eq!(args.exclude_max_uid, Some(998));
        assert_eq!(args.pid_list, Some(vec![123, 456]));
        assert_eq!(
            args.include_uid,
            Some(vec!["1000".to_string(), "1001".to_string()])
        );
    }

    // test that the process-blocking list options (--block-paths, --comm-allow,
    // --comm-deny) parse correctly
    #[test]
    fn test_raw_args_parse_block_paths_and_comm_lists() {
        let args = RawArgs::try_parse_from([
            "panhandle",
            "--block-paths",
            "/usr/bin/nc,/bin/sh",
            "--comm-allow",
            "bash,zsh",
            "--comm-deny",
            "nc,ncat",
        ])
        .unwrap();

        assert_eq!(
            args.block_paths,
            Some(vec!["/usr/bin/nc".to_string(), "/bin/sh".to_string()])
        );
        assert_eq!(
            args.comm_allow,
            Some(vec!["bash".to_string(), "zsh".to_string()])
        );
        assert_eq!(
            args.comm_deny,
            Some(vec!["nc".to_string(), "ncat".to_string()])
        );
    }

    // test that --block-paths entries are accepted right up to MAX_PATH_LENGTH bytes and
    // rejected one byte past it, rather than silently truncating
    #[test]
    fn test_raw_args_parse_block_paths_length_boundary() {
        let at_limit = "a".repeat(MAX_PATH_LENGTH);
        assert!(RawArgs::try_parse_from(["panhandle", "--block-paths", &at_limit]).is_ok());

        let over_limit = "a".repeat(MAX_PATH_LENGTH + 1);
        assert!(RawArgs::try_parse_from(["panhandle", "--block-paths", &over_limit]).is_err());
    }

    // test that --comm-allow/--comm-deny entries are accepted right up to MAX_COMM_LENGTH
    // bytes and rejected one byte past it
    #[test]
    fn test_raw_args_parse_comm_length_boundary() {
        let at_limit = "a".repeat(MAX_COMM_LENGTH);
        assert!(RawArgs::try_parse_from(["panhandle", "--comm-allow", &at_limit]).is_ok());
        assert!(RawArgs::try_parse_from(["panhandle", "--comm-deny", &at_limit]).is_ok());

        let over_limit = "a".repeat(MAX_COMM_LENGTH + 1);
        assert!(RawArgs::try_parse_from(["panhandle", "--comm-allow", &over_limit]).is_err());
        assert!(RawArgs::try_parse_from(["panhandle", "--comm-deny", &over_limit]).is_err());
    }

    // test that --block-paths accepts exactly MAX_BLOCKED_PATHS entries and rejects one
    // more, enforced by clap's num_args upper bound
    #[test]
    fn test_raw_args_parse_block_paths_count_boundary() {
        let at_limit: Vec<String> = (0..MAX_BLOCKED_PATHS)
            .map(|i| format!("/bin/p{i}"))
            .collect();
        assert!(
            RawArgs::try_parse_from(["panhandle", "--block-paths", &at_limit.join(",")]).is_ok()
        );

        // NOTE: clap's num_args upper bound is enforced per raw CLI token, not per
        // value_delimiter-split entry, so it can't reject an over-limit comma-separated
        // list at parse time. The actual limit is enforced downstream in main() via
        // validate_count against MAX_BLOCKED_PATHS -- see test_validate_count_block_paths.
        let over_limit: Vec<String> = (0..MAX_BLOCKED_PATHS + 1)
            .map(|i| format!("/bin/p{i}"))
            .collect();
        let parsed =
            RawArgs::try_parse_from(["panhandle", "--block-paths", &over_limit.join(",")]).unwrap();
        assert_eq!(parsed.block_paths.unwrap().len(), MAX_BLOCKED_PATHS + 1);
    }

    // test that --comm-allow parses at and past MAX_BLOCKED_COMMS entries; like
    // --block-paths, clap's num_args upper bound doesn't reject an over-limit
    // comma-separated list at parse time (see test_raw_args_parse_block_paths_count_boundary),
    // so the actual limit is enforced downstream via validate_count -- see
    // test_validate_count_comm_lists
    #[test]
    fn test_raw_args_parse_comm_allow_count_boundary() {
        let at_limit: Vec<String> = (0..MAX_BLOCKED_COMMS).map(|i| format!("c{i}")).collect();
        let parsed =
            RawArgs::try_parse_from(["panhandle", "--comm-allow", &at_limit.join(",")]).unwrap();
        assert_eq!(parsed.comm_allow.unwrap().len(), MAX_BLOCKED_COMMS);

        let over_limit: Vec<String> = (0..MAX_BLOCKED_COMMS + 1)
            .map(|i| format!("c{i}"))
            .collect();
        let parsed =
            RawArgs::try_parse_from(["panhandle", "--comm-allow", &over_limit.join(",")]).unwrap();
        assert_eq!(parsed.comm_allow.unwrap().len(), MAX_BLOCKED_COMMS + 1);
    }

    // regression test covering every non-bool CLI override field in merge_args at once,
    // so a field that's added later but forgotten in the override list (a copy-paste-prone
    // block of ~10 near-identical `if cli_args.X.is_some() { ... }` statements) is caught
    // here instead of only showing up as a confusing end-to-end config-file bug
    #[tokio::test]
    async fn test_merge_args_overrides_all_scalar_and_list_fields() {
        let config = ConfigArgs {
            exclude_min_uid: Some(1),
            exclude_max_uid: Some(500),
            executables: Some(vec!["/bin/old".to_string()]),
            include_uid: Some(vec!["1".to_string()]),
            memory_faults: Some(1),
            poll: Some(5),
            pid_list: Some(vec![1]),
            syscalls: Some(vec!["old_syscall".to_string()]),
            block_paths: Some(vec!["/old/path".to_string()]),
            comm_allow: Some(vec!["old_allow".to_string()]),
            comm_deny: Some(vec!["old_deny".to_string()]),
            ..Default::default()
        };

        let cli = RawArgs {
            exclude_min_uid: Some(2),
            exclude_max_uid: Some(600),
            executables: Some(vec!["/bin/new".to_string()]),
            include_uid: Some(vec!["2".to_string()]),
            memory_faults: Some(2),
            poll: Some(10),
            pid_list: Some(vec![2]),
            syscalls: Some(vec!["new_syscall".to_string()]),
            block_paths: Some(vec!["/new/path".to_string()]),
            comm_allow: Some(vec!["new_allow".to_string()]),
            comm_deny: Some(vec!["new_deny".to_string()]),
            ..Default::default()
        };

        let merged = merge_args(cli, config).await;

        assert_eq!(merged.exclude_min_uid, Some(2));
        assert_eq!(merged.exclude_max_uid, Some(600));
        assert_eq!(merged.executables, Some(vec!["/bin/new".to_string()]));
        assert_eq!(merged.include_uid, Some(vec!["2".to_string()]));
        assert_eq!(merged.memory_faults, Some(2));
        assert_eq!(merged.poll, Some(10));
        assert_eq!(merged.pid_list, Some(vec![2]));
        assert_eq!(merged.syscalls, Some(vec!["new_syscall".to_string()]));
        assert_eq!(merged.block_paths, Some(vec!["/new/path".to_string()]));
        assert_eq!(merged.comm_allow, Some(vec!["new_allow".to_string()]));
        assert_eq!(merged.comm_deny, Some(vec!["new_deny".to_string()]));
    }

    // test that fields left unset on the CLI pass the config file's value through
    // unchanged, rather than being wiped out by an unconditional overwrite
    #[tokio::test]
    async fn test_merge_args_preserves_config_when_cli_field_unset() {
        let config = ConfigArgs {
            pid_list: Some(vec![42]),
            syscalls: Some(vec!["execve".to_string()]),
            block_paths: Some(vec!["/etc/shadow".to_string()]),
            comm_allow: Some(vec!["sshd".to_string()]),
            ..Default::default()
        };
        let cli = RawArgs {
            ..Default::default()
        };

        let merged = merge_args(cli, config).await;

        assert_eq!(merged.pid_list, Some(vec![42]));
        assert_eq!(merged.syscalls, Some(vec!["execve".to_string()]));
        assert_eq!(merged.block_paths, Some(vec!["/etc/shadow".to_string()]));
        assert_eq!(merged.comm_allow, Some(vec!["sshd".to_string()]));
    }

    // test that merge_args creates the output list from scratch when the config file
    // declares no outputs at all but the CLI provides one or more
    #[tokio::test]
    async fn test_merge_args_creates_outputs_when_config_has_none() {
        // config with no output section
        let config = ConfigArgs {
            ..Default::default()
        };
        // CLI specifies file, http, and syslog together
        let cli = RawArgs {
            output: Some(OutputCommand::Output {
                file: Some(PathBuf::from("/tmp/panhandle.log")),
                http: Some("http://localhost:4319/raw-audit".to_string()),
                syslog: Some(Some("localhost:514/tcp".to_string())),
            }),
            ..Default::default()
        };

        let merged = merge_args(cli, config).await;

        // all three outputs survive the merge into a single OutputCommand
        assert_eq!(
            merged.output,
            Some(OutputCommand::Output {
                file: Some(PathBuf::from("/tmp/panhandle.log")),
                http: Some("http://localhost:4319/raw-audit".to_string()),
                syslog: Some(Some("localhost:514/tcp".to_string())),
            })
        );
    }

    // test that a CLI output subcommand with only some fields set still merges into an
    // existing config output list without disturbing the other entries
    #[tokio::test]
    async fn test_merge_args_output_partial_update_nonempty() {
        // config declares file + syslog outputs
        let config = ConfigArgs {
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
        // CLI only overrides the syslog destination (matching test_merge_args_valid's
        // documented intent of keeping the file option untouched)
        let cli = RawArgs {
            output: Some(OutputCommand::Output {
                file: None,
                http: None,
                syslog: Some(Some("unix".to_string())),
            }),
            ..Default::default()
        };

        let merged = merge_args(cli, config).await;

        // the config's file output survives untouched, only the syslog destination is
        // overridden, all collapsed into a single OutputCommand
        assert_eq!(
            merged.output,
            Some(OutputCommand::Output {
                file: Some(PathBuf::from("/var/log/panhandle/panhandle.log")),
                http: None,
                syslog: Some(Some("unix".to_string())),
            })
        );
    }

    // regression test: a CLI output type the config file never declared must still take
    // effect. The merge previously only rewrote entries already present in the config's
    // output list, so an --http endpoint given on the command line against a config
    // declaring only file/syslog (as the shipped /opt/panhandle/panhandle.yaml does) was
    // silently discarded, contrary to the documented CLI-overrides-config precedence.
    #[tokio::test]
    async fn test_merge_args_adds_cli_output_type_absent_from_config() {
        // config declares file + syslog, but no http endpoint
        let config = ConfigArgs {
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
        // CLI adds an http endpoint the config never mentioned
        let cli = RawArgs {
            output: Some(OutputCommand::Output {
                file: None,
                http: Some("http://localhost:4319/raw-audit".to_string()),
                syslog: None,
            }),
            ..Default::default()
        };

        let merged = merge_args(cli, config).await;

        // the config's file/syslog outputs survive untouched and the CLI's http endpoint
        // is added rather than dropped
        assert_eq!(
            merged.output,
            Some(OutputCommand::Output {
                file: Some(PathBuf::from("/var/log/panhandle/panhandle.log")),
                http: Some("http://localhost:4319/raw-audit".to_string()),
                syslog: Some(Some("hpcsyslog.lanl.gov:514/tcp".to_string())),
            })
        );
    }

    // test that hex_to_interface decodes an IPv4 hex address (as found in /proc/net/tcp),
    // matches it to the owning interface, excludes loopback addresses, and returns None
    // for both IPv6-length hex and malformed input
    #[test]
    fn test_hex_to_interface() {
        use std::net::Ipv4Addr;

        use network_interface::{Addr, NetworkInterface, V4IfAddr};

        let iface = NetworkInterface {
            name: "eth0".to_string(),
            addr: vec![Addr::V4(V4IfAddr {
                ip: Ipv4Addr::new(10, 0, 0, 5),
                broadcast: None,
                netmask: None,
            })],
            mac_addr: Some("aa:bb:cc:dd:ee:ff".to_string()),
            index: 1,
            internal: false,
        };
        let interfaces = vec![iface];

        // loopback (127.0.0.1 in /proc/net/tcp's little-endian hex form) is always
        // excluded, even though no interface here happens to match it
        assert_eq!(hex_to_interface("0100007F", &interfaces), None);

        // 10.0.0.5 encoded the same way resolves to the matching interface
        assert_eq!(
            hex_to_interface("0500000A", &interfaces),
            Some(("eth0".to_string(), "10.0.0.5".to_string()))
        );

        // a well-formed address that matches no known interface returns None
        assert_eq!(hex_to_interface("01000A0A", &interfaces), None);

        // IPv6-length hex (32 chars) is skipped entirely rather than misparsed
        assert_eq!(hex_to_interface(&"0".repeat(32), &interfaces), None);

        // malformed hex yields None rather than panicking
        assert_eq!(hex_to_interface("not_hex!", &interfaces), None);
    }

    // test get_network_info's fallback chain: an all-unknown result when there's no
    // matching connection and no usable non-loopback interface, then falling back to the
    // first non-"lo" interface with an address once one is available
    #[test]
    fn test_get_network_info_fallback_and_unknown() {
        use std::net::Ipv4Addr;

        use network_interface::{Addr, NetworkInterface, V4IfAddr};

        // guaranteed not to be a real running process, so get_active_connection_info's
        // /proc/<pid>/net/{tcp,tcp6,udp} reads all fail and it deterministically returns
        // None, exercising get_network_info's fallback path
        let nonexistent_pid = u32::MAX;

        // no interfaces at all -> fully unknown fallback
        assert_eq!(
            get_network_info(nonexistent_pid, &[]),
            (
                "unknown".to_string(),
                "0.0.0.0".to_string(),
                "00:00:00:00:00:00".to_string()
            )
        );

        // only "lo" present -> still falls through to fully unknown, since the fallback
        // loop explicitly skips "lo"
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
            get_network_info(nonexistent_pid, std::slice::from_ref(&lo)),
            (
                "unknown".to_string(),
                "0.0.0.0".to_string(),
                "00:00:00:00:00:00".to_string()
            )
        );

        // a non-"lo" interface with an address is used as the fallback default
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
            get_network_info(nonexistent_pid, &[lo, eth0]),
            (
                "eth0".to_string(),
                "192.168.1.10".to_string(),
                "11:22:33:44:55:66".to_string()
            )
        );
    }

    // test that get_process_name resolves the current process's own comm, and returns
    // None for a PID that can't possibly exist
    #[test]
    fn test_get_process_name() {
        let pid = std::process::id();
        let name = get_process_name(pid);
        assert!(name.is_some_and(|n| !n.is_empty()));

        assert_eq!(get_process_name(u32::MAX), None);
    }

    // test that get_parent_pid returns the same value as independently reading
    // /proc/self/status's PPid field, and errors for a PID that can't possibly exist
    #[test]
    fn test_get_parent_pid() {
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

    // test that get_process_uid returns the same value as independently reading
    // /proc/self/status's real UID (the first of the four values on the "Uid:" line), and
    // None for a PID that can't possibly exist
    #[test]
    fn test_get_process_uid() {
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

    // test that resolve_username resolves the current process's own real UID to a
    // non-empty name, and falls back to "unknown" (rather than panicking) for a UID that
    // can't possibly map to a real user
    #[test]
    fn test_resolve_username() {
        let pid = std::process::id();
        let uid = get_process_uid(pid).expect("status should succeed for the current process");
        assert!(!resolve_username(uid).is_empty());

        assert_eq!(resolve_username(u32::MAX), "unknown");
    }

    // test that json_quoted escapes every JSON-hostile character class (quotes,
    // backslashes, control chars) and that the escaped output round-trips through a real
    // serde_json parse back to the original string unchanged
    #[test]
    fn test_json_quoted_escaping() {
        // plain strings pass through wrapped in quotes
        assert_eq!(json_quoted("plain"), "\"plain\"");
        // embedded quotes are backslash-escaped
        assert_eq!(json_quoted("say \"hi\""), "\"say \\\"hi\\\"\"");
        // backslashes are doubled
        assert_eq!(json_quoted("a\\b"), "\"a\\\\b\"");
        // control characters (here ESC) become \u escapes, not raw bytes
        assert_eq!(json_quoted("esc\u{1b}ape"), "\"esc\\u001bape\"");
        // the escaped output must parse back to the original, byte for byte
        let hostile = "q\"\\\u{1b}\n\t";
        assert_eq!(
            json_quoted(hostile),
            serde_json::to_string(hostile).unwrap()
        );
        let roundtrip: String = serde_json::from_str(&json_quoted(hostile)).unwrap();
        assert_eq!(roundtrip, hostile);
    }

    // test format_owner's rendering for every combination of resolved/unresolved
    // uid/username -- in particular that a resolvable uid of 0 (root) renders as "0", not
    // "unknown", so it stays distinguishable from a genuinely unresolved uid
    #[test]
    fn test_format_owner() {
        assert_eq!(
            format_owner(Some(0), Some("root")),
            ("0".to_string(), "root".to_string())
        );
        assert_eq!(
            format_owner(Some(1000), Some("dmcgee")),
            ("1000".to_string(), "dmcgee".to_string())
        );
        // uid resolved but username lookup failed
        assert_eq!(
            format_owner(Some(100998), Some("unknown")),
            ("100998".to_string(), "unknown".to_string())
        );
        // uid itself couldn't be resolved at all
        assert_eq!(
            format_owner(None, Some("unknown")),
            ("unknown".to_string(), "unknown".to_string())
        );
        assert_eq!(
            format_owner(None, None),
            ("unknown".to_string(), "unknown".to_string())
        );
    }

    // test format_state's rendering of a present vs. absent process state
    #[test]
    fn test_format_state() {
        assert_eq!(format_state(Some('R')), "R");
        assert_eq!(format_state(Some('S')), "S");
        assert_eq!(format_state(None), "");
    }

    // test format_state_prose's human-readable rendering of every /proc state char,
    // including the fallback for an unrecognized or absent state
    #[test]
    fn test_format_state_prose() {
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

    // test the CPU plain-text builder: verbose mode carries parent/owner/state and timing
    // fields, compact mode keeps just PID/comm plus the CPU percentages
    #[test]
    fn test_format_cpu_prose() {
        let verbose = format_cpu_prose(
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
        assert_eq!(
            verbose,
            "Type: cpu, PID: 42, Comm: bash, Parent PID: 1, Parent Comm: systemd, User ID: 0, User: root, State: sleeping, Total Time: 1234.50 ms, Delta Time: 56.25 ms, CPU: 12.50%, Avg CPU: 7.25%, Max CPU: 90.00%"
        );

        let compact = format_cpu_prose(
            false, 42, "bash", None, None, None, None, None, 0.0, 0.0, 12.5, 7.25, 90.0,
        );
        assert_eq!(
            compact,
            "Type: cpu, PID: 42, Comm: bash, CPU: 12.50%, Avg CPU: 7.25%, Max CPU: 90.00%"
        );
    }

    // test the CPU not-found builder, which reports a process that vanished between the
    // scan and report phases
    #[test]
    fn test_format_cpu_not_found_prose() {
        let verbose = format_cpu_not_found_prose(
            true,
            42,
            "bash",
            Some(1),
            Some("systemd"),
            Some(0),
            Some("root"),
        );
        assert_eq!(
            verbose,
            "Type: cpu, PID: 42, Comm: bash, Parent PID: 1, Parent Comm: systemd, User ID: 0, User: root, Status: not_found"
        );

        let compact = format_cpu_not_found_prose(false, 42, "bash", None, None, None, None);
        assert_eq!(compact, "Type: cpu, PID: 42, Comm: bash, Status: not_found");
    }

    // test the system-wide CPU summary builder: 100% = all cores busy, with the core
    // count and busy delta rendered alongside the percentage
    #[test]
    fn test_format_system_cpu_prose() {
        let summary = format_system_cpu_prose(25.0, 4, 1000.0);
        assert_eq!(
            summary,
            "Type: cpu, CPU: 25.00%, CPUs: 4, Busy Delta: 1000.00 ms"
        );
    }

    // test the per-process GPU plain-text builder in both modes
    #[test]
    fn test_format_gpu_prose() {
        let verbose = format_gpu_prose(
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
        assert_eq!(
            verbose,
            "Type: gpu, PID: 42, Comm: nvidia-smi, Parent PID: 1, Parent Comm: systemd, User ID: 0, User: root, GPU: 0, VRAM: 25%, Encoder: 10%, Decoder: 5%"
        );

        let compact = format_gpu_prose(
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
        assert_eq!(
            compact,
            "Type: gpu, PID: 42, Comm: nvidia-smi, GPU: 0, VRAM: 25%, Encoder: 10%, Decoder: 5%"
        );
    }

    // test the per-GPU summary builder, in particular that the temperature renders with a
    // degree symbol and no space before it
    #[test]
    fn test_format_gpu_summary_prose() {
        let summary = format_gpu_summary_prose("0", 90, 80, 4096, 30, 20, 65);
        assert_eq!(
            summary,
            "Type: gpu, GPU: 0, Utilization: 90%, VRAM: 80%, VRAM Used: 4096 MB, Encoder: 30%, Decoder: 20%, Temperature: 65°C"
        );
    }

    // test the IO plain-text builder in both modes
    #[test]
    fn test_format_io_prose() {
        let verbose = format_io_prose(
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
        assert_eq!(
            verbose,
            "Type: io, PID: 42, Comm: bash, Parent PID: 1, Parent Comm: systemd, User ID: 0, User: root, State: sleeping, Read Count: 100, Write Count: 50, Read: 1024 MB, Write: 512 MB, Open FDs: 12, Unique Inodes: 10"
        );

        let compact = format_io_prose(
            false, 42, "bash", None, None, None, None, None, 100, 50, 1024, 512, 12, 10,
        );
        assert_eq!(
            compact,
            "Type: io, PID: 42, Comm: bash, Read Count: 100, Write Count: 50, Read: 1024 MB, Write: 512 MB, Open FDs: 12, Unique Inodes: 10"
        );
    }

    // test the major-faults plain-text builder in both modes
    #[test]
    fn test_format_faults_prose() {
        let verbose = format_faults_prose(
            true,
            42,
            "bash",
            Some(1),
            Some("systemd"),
            Some(0),
            Some("root"),
            Some('S'),
            1234,
            5678,
        );
        assert_eq!(
            verbose,
            "Type: fault, PID: 42, Comm: bash, Parent PID: 1, Parent Comm: systemd, User ID: 0, User: root, State: sleeping, Major Faults: 1234, Child Major Faults: 5678"
        );

        let compact =
            format_faults_prose(false, 42, "bash", None, None, None, None, None, 1234, 5678);
        assert_eq!(
            compact,
            "Type: fault, PID: 42, Comm: bash, Major Faults: 1234, Child Major Faults: 5678"
        );
    }

    // test the memory plain-text builder in both modes
    #[test]
    fn test_format_mem_prose() {
        let verbose = format_mem_prose(
            true,
            42,
            "bash",
            Some(1),
            Some("systemd"),
            Some(0),
            Some("root"),
            Some('S'),
            128,
            32768,
            256,
            1024,
            64,
            32,
        );
        assert_eq!(
            verbose,
            "Type: mem, PID: 42, Comm: bash, Parent PID: 1, Parent Comm: systemd, User ID: 0, User: root, State: sleeping, RSS: 128 MB (32768 pages), Peak RSS: 256 MB, Virtual Size: 1024 MB, Shared: 64 MB, Data + Stack: 32 MB"
        );

        let compact = format_mem_prose(
            false, 42, "bash", None, None, None, None, None, 128, 32768, 256, 1024, 64, 32,
        );
        assert_eq!(
            compact,
            "Type: mem, PID: 42, Comm: bash, RSS: 128 MB (32768 pages), Peak RSS: 256 MB, Virtual Size: 1024 MB, Shared: 64 MB, Data + Stack: 32 MB"
        );
    }

    // test the socket plain-text builder in both modes, including the MB conversion of
    // the byte counters performed by the caller
    #[test]
    fn test_format_socket_prose() {
        let stats = NetStats {
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

        let verbose = format_socket_prose(
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
        assert_eq!(
            verbose,
            "Type: sock, PID: 42, Comm: sshd, Parent PID: 1, Parent Comm: systemd, User ID: 0, User: root, State: sleeping, NIC: eth0, IP: 192.168.1.10, MAC: aa:bb:cc:dd:ee:ff, Established: 5, Syn Recv: 1, Close Wait: 2, Fin Wait: 4, Time Wait: 3, UDP: 6, Sent: 10 MB, Received: 20 MB, Packets Sent: 100, Packets Received: 200"
        );

        let compact = format_socket_prose(
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
        assert_eq!(
            compact,
            "Type: sock, PID: 42, Comm: sshd, NIC: eth0, IP: 192.168.1.10, MAC: aa:bb:cc:dd:ee:ff, Established: 5, Syn Recv: 1, Close Wait: 2, Fin Wait: 4, Time Wait: 3, UDP: 6, Sent: 10 MB, Received: 20 MB, Packets Sent: 100, Packets Received: 200"
        );
    }

    // test that build_found_entry converts ticks to ns correctly, treats a missing prior
    // sample as a zero delta (the first-sample-spike fix covered end-to-end by
    // test_calc_delta), and accumulates running avg/max correctly across repeated samples
    #[test]
    fn test_build_found_entry_delta_and_accumulation() {
        use std::collections::HashMap;

        use procfs::process::Process;

        let pid = std::process::id();
        let stat = Process::new(pid as i32)
            .and_then(|p| p.stat())
            .expect("stat should succeed for the current process");
        let ticks_per_second = procfs::ticks_per_second();
        let expected_cpu_time = (stat.utime + stat.stime) * 1_000_000_000 / ticks_per_second;
        let interval_ns = 1_000_000_000u64;

        let mut last_pid_times: HashMap<u32, u64> = HashMap::new();
        // seed a "last" of 0 so the first call sees the full cpu_time as its delta
        last_pid_times.insert(pid, 0);
        let mut pid_stats = HashMap::new();

        let e1 = build_found_entry(
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
        let expected_percent1 = calc_cpu_percent(expected_cpu_time, interval_ns);
        assert_eq!(e1.cpu_percent, expected_percent1);
        assert_eq!(e1.avg_cpu_percent, expected_percent1);
        assert_eq!(e1.max_cpu_percent, expected_percent1);
        assert_eq!(last_pid_times[&pid], expected_cpu_time);

        // second sample of the identical stat snapshot -> zero elapsed cpu time, so cpu%
        // drops to 0 while avg reflects both samples and max holds the first sample's peak
        let e2 = build_found_entry(
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

    fn zero_execve_event() -> ExecveEvent {
        ExecveEvent {
            timestamp: 0,
            argv: [[0u8; ARG_SIZE]; ARG_COUNT],
            envp: [[0u8; ENV_SIZE]; ENV_COUNT],
            pid: 42,
            gid: 100,
            uid: 1000,
            tgid: 42,
            command: [0u8; 16],
            filename: [0u8; LEN_MAX_PATH],
        }
    }

    // Debug of a fully zeroed event must not panic: the old two-pass count/write logic
    // underflowed `item_count - 1` when the first scratch slot was already the NUL
    // terminator (panic in debug builds, garbage output in release).
    #[test]
    fn test_execve_event_debug_zeroed() {
        let evt = zero_execve_event();
        let s = format!("{:?}", evt);
        let expected = format!(
            "{{\"filename\": \"{}\", \"command\": \"{}\", \"uid\": \"1000\", \"pid\": \"42\", \"gid\": \"100\", \"tgid\": \"42\", \"args\": [], \"envs\": []}}",
            "\0".repeat(LEN_MAX_PATH),
            "\0".repeat(16),
        );
        assert_eq!(s, expected);
    }

    // Debug of a populated event renders args and envs in order, NUL-padded to the
    // fixed slot sizes, joined with ", ".
    #[test]
    fn test_execve_event_debug_populated() {
        let mut evt = zero_execve_event();
        evt.argv[0][..2].copy_from_slice(b"-c");
        evt.argv[1][..4].copy_from_slice(b"echo");
        evt.envp[0][..5].copy_from_slice(b"PATH=");
        let s = format!("{:?}", evt);
        let expected = format!(
            "{{\"filename\": \"{}\", \"command\": \"{}\", \"uid\": \"1000\", \"pid\": \"42\", \"gid\": \"100\", \"tgid\": \"42\", \"args\": [\"-c{}\", \"echo{}\"], \"envs\": [\"PATH={}\"]}}",
            "\0".repeat(LEN_MAX_PATH),
            "\0".repeat(16),
            "\0".repeat(ARG_SIZE - 2),
            "\0".repeat(ARG_SIZE - 4),
            "\0".repeat(ENV_SIZE - 5),
        );
        assert_eq!(s, expected);
    }

    // Invalid UTF-8 in a scratch slot used to panic via `.chars().nth(0).unwrap()`
    // (from_utf8 fails -> unwrap_or_default -> empty string). The list must instead
    // end at the first unparseable slot without panicking.
    #[test]
    fn test_execve_event_debug_invalid_utf8() {
        let mut evt = zero_execve_event();
        evt.argv[0][..2].copy_from_slice(b"-c");
        evt.argv[1][0] = 0xFF; // invalid UTF-8 start byte in the second slot
        let s = format!("{:?}", evt);
        assert!(s.contains("\"args\": [\"-c"));
        assert!(!s.contains("echo"));
        assert!(s.contains("\"envs\": []"));
    }

    // Display must survive the same zeroed/invalid-UTF-8 inputs without panicking.
    #[test]
    fn test_execve_event_display_zeroed() {
        let evt = zero_execve_event();
        let s = format!("{}", evt);
        let expected = format!(
            "filename: {}, command: {}, uid: 1000, pid: 42, gid: 100, tgid: 42, args: [], envs: []",
            "\0".repeat(LEN_MAX_PATH),
            "\0".repeat(16),
        );
        assert_eq!(s, expected);
    }

    #[test]
    fn test_execve_event_display_populated() {
        let mut evt = zero_execve_event();
        evt.argv[0][..2].copy_from_slice(b"-c");
        evt.argv[1][..4].copy_from_slice(b"echo");
        evt.envp[0][..5].copy_from_slice(b"PATH=");
        let s = format!("{}", evt);
        let expected = format!(
            "filename: {}, command: {}, uid: 1000, pid: 42, gid: 100, tgid: 42, args: [-c{},echo{},], envs: [PATH={},]",
            "\0".repeat(LEN_MAX_PATH),
            "\0".repeat(16),
            "\0".repeat(ARG_SIZE - 2),
            "\0".repeat(ARG_SIZE - 4),
            "\0".repeat(ENV_SIZE - 5),
        );
        assert_eq!(s, expected);
    }

    #[test]
    fn test_execve_event_display_invalid_utf8() {
        let mut evt = zero_execve_event();
        evt.argv[0][0] = 0xFF;
        let s = format!("{}", evt);
        assert!(s.contains("args: []"));
        assert!(s.contains("envs: []"));
    }

    // helper shared by the JSON-validity tests: every format_*_json builder must emit a
    // document that serde_json can parse back, so each one gets a parse assertion here
    fn assert_valid_json(json: &str) {
        serde_json::from_str::<serde_json::Value>(json)
            .unwrap_or_else(|e| panic!("builder emitted invalid JSON: {e}\njson: {json}"));
    }

    // every CPU JSON builder emits parseable documents in both verbose and compact modes,
    // including for a comm containing quotes/backslashes/control chars, and the escaped
    // value round-trips through the parser unchanged
    #[test]
    fn test_cpu_json_valid() {
        let hostile = "ba\"sh\\\u{1b}[31m";

        let verbose = format_cpu_json(
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
        assert_valid_json(&verbose);
        // verbose mode carries the owner/state/accumulation fields with their values
        let parsed_verbose: serde_json::Value = serde_json::from_str(&verbose).unwrap();
        assert_eq!(parsed_verbose["PPID"], 1);
        assert_eq!(parsed_verbose["UID"], "0");
        assert_eq!(parsed_verbose["State"], "S");
        assert_eq!(parsed_verbose["Total_Time_ms"], 1234.5);
        assert_eq!(parsed_verbose["Delta_Time_ms"], 56.25);

        let compact = format_cpu_json(
            false, 42, hostile, None, None, None, None, None, 0.0, 0.0, 12.5, 7.25, 90.0,
        );
        assert_valid_json(&compact);
        let parsed: serde_json::Value = serde_json::from_str(&compact).unwrap();
        assert_eq!(parsed["Comm"], hostile);
        assert_eq!(parsed["Type"], "cpu");
        // the numeric percentage fields survive the {:.2} formatting unchanged
        assert_eq!(parsed["CPU%"], 12.5);
        assert_eq!(parsed["Avg_CPU%"], 7.25);
        assert_eq!(parsed["Max_CPU%"], 90.0);

        let not_found_verbose = format_cpu_not_found_json(
            true,
            42,
            hostile,
            Some(1),
            Some("systemd"),
            Some(0),
            Some("root"),
        );
        assert_valid_json(&not_found_verbose);

        let not_found_compact =
            format_cpu_not_found_json(false, 42, hostile, None, None, None, None);
        assert_valid_json(&not_found_compact);

        let system = format_system_cpu_json(42.5, 8, 1234.5);
        assert_valid_json(&system);
    }

    // the GPU builders must emit parseable documents in both modes; the summary in
    // particular must quote the NVML UUID-style GPU_ID (regression: the old unquoted
    // interpolation emitted invalid JSON for UUID ids)
    #[test]
    fn test_gpu_json_valid() {
        let hostile = "nvidia-smi\"\\\u{1b}";

        let verbose = format_gpu_process_json(
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
        assert_valid_json(&verbose);
        // verbose mode carries the owner fields with their values
        let parsed_verbose: serde_json::Value = serde_json::from_str(&verbose).unwrap();
        assert_eq!(parsed_verbose["PPID"], 1);
        assert_eq!(parsed_verbose["UID"], "0");
        assert_eq!(parsed_verbose["Username"], "root");
        assert_eq!(parsed_verbose["GPU_ID"], 0);

        let compact =
            format_gpu_process_json(false, 42, hostile, None, None, None, None, 0, 25, 10, 5);
        assert_valid_json(&compact);
        let parsed: serde_json::Value = serde_json::from_str(&compact).unwrap();
        assert_eq!(parsed["Comm"], hostile);

        let uuid = "GPU-6e6f2c5a-6c1e-8b3a-4a2f-0d2c1b4a9e8f";
        let summary = format_gpu_summary_json(uuid, 90, 80, 4096, 30, 20, 65);
        assert_valid_json(&summary);
        let parsed: serde_json::Value = serde_json::from_str(&summary).unwrap();
        assert_eq!(parsed["GPU_ID"], uuid);
        assert_eq!(parsed["Temperature_C"], 65);
    }

    // the IO JSON builder emits parseable documents in both modes, with the hostile
    // comm escaping through the parser unchanged
    #[test]
    fn test_io_json_valid() {
        let hostile = "bash\"\\\u{1b}[31m";

        let verbose = format_io_json(
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
        assert_valid_json(&verbose);
        // verbose mode carries the owner and state fields with their values
        let parsed_verbose: serde_json::Value = serde_json::from_str(&verbose).unwrap();
        assert_eq!(parsed_verbose["PPID"], 1);
        assert_eq!(parsed_verbose["UID"], "0");
        assert_eq!(parsed_verbose["State"], "S");
        assert_eq!(parsed_verbose["Open_FDs"], 12);

        let compact = format_io_json(
            false, 42, hostile, None, None, None, None, None, 100, 50, 1024, 512, 12, 10,
        );
        assert_valid_json(&compact);
        let parsed: serde_json::Value = serde_json::from_str(&compact).unwrap();
        assert_eq!(parsed["Comm"], hostile);
        assert_eq!(parsed["Open_FDs"], 12);
    }

    // the socket JSON builder emits parseable documents in both modes, with NIC/IP/MAC
    // strings escaping through the parser unchanged
    #[test]
    fn test_socket_json_valid() {
        let stats = NetStats {
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

        let verbose = format_socket_json(
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
        assert_valid_json(&verbose);
        // verbose mode carries the owner and state fields with their values
        let parsed_verbose: serde_json::Value = serde_json::from_str(&verbose).unwrap();
        assert_eq!(parsed_verbose["PPID"], 1);
        assert_eq!(parsed_verbose["UID"], "0");
        assert_eq!(parsed_verbose["State"], "S");
        assert_eq!(parsed_verbose["ESTAB"], 5);

        let compact = format_socket_json(
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
        assert_valid_json(&compact);
        let parsed: serde_json::Value = serde_json::from_str(&compact).unwrap();
        assert_eq!(parsed["Comm"], hostile);
        assert_eq!(parsed["MAC"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(parsed["ESTAB"], 5);
    }

    // the faults and memory JSON builders emit parseable documents in both modes
    #[test]
    fn test_faults_and_mem_json_valid() {
        let hostile = "bash\"\\\u{1b}";

        let faults_verbose = format_faults_json(
            true,
            42,
            hostile,
            Some(1),
            Some("systemd"),
            Some(0),
            Some("root"),
            Some('S'),
            1234,
            5678,
        );
        assert_valid_json(&faults_verbose);
        // verbose mode carries the owner and state fields with their values
        let parsed_faults_verbose: serde_json::Value =
            serde_json::from_str(&faults_verbose).unwrap();
        assert_eq!(parsed_faults_verbose["PPID"], 1);
        assert_eq!(parsed_faults_verbose["UID"], "0");
        assert_eq!(parsed_faults_verbose["State"], "S");
        assert_eq!(parsed_faults_verbose["Maj_Faults"], 1234);

        let faults_compact =
            format_faults_json(false, 42, hostile, None, None, None, None, None, 1234, 5678);
        assert_valid_json(&faults_compact);

        let mem_verbose = format_mem_json(
            true,
            42,
            hostile,
            Some(1),
            Some("systemd"),
            Some(0),
            Some("root"),
            Some('S'),
            128,
            32768,
            256,
            1024,
            64,
            32,
        );
        assert_valid_json(&mem_verbose);
        // verbose mode carries the owner and state fields with their values
        let parsed_mem_verbose: serde_json::Value = serde_json::from_str(&mem_verbose).unwrap();
        assert_eq!(parsed_mem_verbose["PPID"], 1);
        assert_eq!(parsed_mem_verbose["UID"], "0");
        assert_eq!(parsed_mem_verbose["State"], "S");
        assert_eq!(parsed_mem_verbose["RSS_MB"], 128);

        let mem_compact = format_mem_json(
            false, 42, hostile, None, None, None, None, None, 128, 32768, 256, 1024, 64, 32,
        );
        assert_valid_json(&mem_compact);
        let parsed: serde_json::Value = serde_json::from_str(&mem_compact).unwrap();
        assert_eq!(parsed["Comm"], hostile);
        assert_eq!(parsed["RSS_MB"], 128);
    }

    // the shell and execve event JSON builders emit parseable documents when the
    // free-form command/entry/args/envs contain quotes, backslashes, and control chars
    #[test]
    fn test_shell_and_execve_json_valid() {
        let hostile_entry = "echo \"hi\" \\\u{1b}[31m";

        let shell = format_shell_event_json(
            "node1",
            "dmcgee",
            hostile_entry,
            "bash -c 'x'",
            1000,
            42,
            100,
            42,
            "2026-08-13_10:00:00",
        );
        assert_valid_json(&shell);
        let parsed: serde_json::Value = serde_json::from_str(&shell).unwrap();
        // every schema field round-trips with its exact value
        assert_eq!(parsed["application"], "panhandle");
        assert_eq!(parsed["hostname"], "node1");
        assert_eq!(parsed["moniker"], "dmcgee");
        assert_eq!(parsed["entry"], hostile_entry);
        assert_eq!(parsed["command"], "bash -c 'x'");
        assert_eq!(parsed["uid"], "1000");
        assert_eq!(parsed["pid"], "42");
        assert_eq!(parsed["gid"], "100");
        assert_eq!(parsed["tgid"], "42");
        assert_eq!(parsed["ts_utc"], "2026-08-13_10:00:00");

        let execve = format_execve_event_json(
            "node1",
            "dmcgee",
            "/bin/echo",
            "echo \"hi\"",
            1000,
            42,
            100,
            42,
            &["-c", "\"quoted\""],
            &["PATH=/usr/bin", "TERM=\u{1b}[31m"],
            "2026-08-13_10:00:00",
        );
        assert_valid_json(&execve);
        let parsed: serde_json::Value = serde_json::from_str(&execve).unwrap();
        // every schema field round-trips with its exact value
        assert_eq!(parsed["application"], "panhandle");
        assert_eq!(parsed["hostname"], "node1");
        assert_eq!(parsed["moniker"], "dmcgee");
        assert_eq!(parsed["filename"], "/bin/echo");
        assert_eq!(parsed["command"], "echo \"hi\"");
        assert_eq!(parsed["uid"], "1000");
        assert_eq!(parsed["pid"], "42");
        assert_eq!(parsed["gid"], "100");
        assert_eq!(parsed["tgid"], "42");
        assert_eq!(parsed["args"], serde_json::json!(["-c", "\"quoted\""]));
        assert_eq!(
            parsed["envs"],
            serde_json::json!(["PATH=/usr/bin", "TERM=\u{1b}[31m"])
        );
        assert_eq!(parsed["ts_utc"], "2026-08-13_10:00:00");
    }

    // test that Readline's Display impl renders the fixed schema, trimming the trailing
    // nulls that pad the fixed-size byte arrays (and any surrounding whitespace), while
    // a zeroed struct still renders a complete, parseable line
    #[test]
    fn test_readline_display() {
        let mut entry = [0u8; ARG_SIZE];
        let text = b"ls -la";
        entry[..text.len()].copy_from_slice(text);
        let mut command = [0u8; 16];
        command[..4].copy_from_slice(b"bash");

        let line = Readline {
            timestamp: 1000,
            uid: 1000,
            gid: 100,
            pid: 42,
            tgid: 42,
            command,
            entry,
        };
        assert_eq!(
            line.to_string(),
            "entry: ls -la, command: bash, uid: 1000, pid: 42, gid: 100, tgid: 42"
        );

        let zeroed = Readline {
            timestamp: 0,
            uid: 0,
            gid: 0,
            pid: 0,
            tgid: 0,
            command: [0u8; 16],
            entry: [0u8; ARG_SIZE],
        };
        assert_eq!(
            zeroed.to_string(),
            "entry: , command: , uid: 0, pid: 0, gid: 0, tgid: 0"
        );
    }
}
