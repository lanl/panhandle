//! Integration tests for config file loading and CLI argument merging.
//! Tests that work without requiring root or eBPF:
//! - Config parsing errors (fail before root check)
//! - --version, --help (exit before root check)
//! - Argument validation errors: out-of-range/malformed values and list
//!   count/length limits, from both the CLI and the config file
//!   (validate_args_or_exit in main.rs runs all of these before the root
//!   check specifically so they're reachable here)

use std::fs;
use std::process::{Command, Stdio};

fn panhandle_bin() -> Command {
    let bin_path = env!("CARGO_BIN_EXE_panhandle");
    let mut cmd = Command::new(bin_path);
    cmd.env("PANHANDLE_TEST_MODE", "1");
    cmd.stdin(Stdio::null());
    cmd
}

/// Test that invalid config files are rejected with clear errors
#[test]
fn test_invalid_config_rejected() {
    let config_path = "/tmp/panhandle_invalid.yaml";
    fs::write(config_path, "invalid: [unclosed").unwrap();

    let output = panhandle_bin()
        .args(["--config", config_path])
        .output()
        .expect("Failed to execute panhandle");

    assert!(
        !output.status.success(),
        "invalid config should cause failure"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Invalid YAML config") || combined.contains("config"),
        "error should mention config/YAML issue, got: {}",
        combined
    );
}

/// Test that unknown config fields are rejected (deny_unknown_fields)
#[test]
fn test_unknown_config_field_rejected() {
    let config_path = "/tmp/panhandle_unknown.yaml";
    fs::write(config_path, "unknown_field: true\n").unwrap();

    let output = panhandle_bin()
        .args(["--config", config_path])
        .output()
        .expect("Failed to execute panhandle");

    assert!(
        !output.status.success(),
        "unknown field should cause failure"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("unknown") || combined.contains("Invalid"),
        "error should mention unknown field, got: {}",
        combined
    );
}

/// Test that config file not found is handled gracefully
#[test]
fn test_nonexistent_config_rejected() {
    let output = panhandle_bin()
        .args(["--config", "/nonexistent/path/config.yaml"])
        .output()
        .expect("Failed to execute panhandle");

    assert!(!output.status.success(), "nonexistent config should fail");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("not found") || combined.contains("Config file"),
        "error should mention file not found, got: {}",
        combined
    );
}

/// Test that unsupported config extensions are rejected
#[test]
fn test_unsupported_config_extension_rejected() {
    let config_path = "/tmp/panhandle_test.xml";
    fs::write(config_path, "<config></config>").unwrap();

    let output = panhandle_bin()
        .args(["--config", config_path])
        .output()
        .expect("Failed to execute panhandle");

    assert!(!output.status.success(), "XML config should fail");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Unsupported config type") || combined.contains("xml"),
        "error should mention unsupported type, got: {}",
        combined
    );
}

/// Test that the binary outputs version correctly
#[test]
fn test_version_output() {
    let output = panhandle_bin()
        .args(["--version"])
        .output()
        .expect("Failed to execute panhandle");

    assert!(output.status.success(), "--version should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("panhandle"),
        "version output should contain binary name"
    );
}

/// Test that help output works
#[test]
fn test_help_output() {
    let output = panhandle_bin()
        .args(["--help"])
        .output()
        .expect("Failed to execute panhandle");

    assert!(output.status.success(), "--help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--bash"),
        "help should mention --bash option"
    );
    assert!(stdout.contains("--zsh"), "help should mention --zsh option");
    assert!(stdout.contains("--cpu"), "help should mention --cpu option");
}

/// Test that subcommand 'output' help works
#[test]
fn test_output_subcommand_help() {
    let output = panhandle_bin()
        .args(["output", "--help"])
        .output()
        .expect("Failed to execute panhandle");

    assert!(output.status.success(), "output --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--file"),
        "output help should mention --file"
    );
    assert!(
        stdout.contains("--http"),
        "output help should mention --http"
    );
    assert!(
        stdout.contains("--syslog"),
        "output help should mention --syslog"
    );
}

/// Test that a non-numeric --include-uid value produces a clean error rather than
/// panicking. Regression test for an unguarded .parse::<u32>().unwrap() on this value.
#[test]
fn test_include_uid_non_numeric_rejected() {
    let output = panhandle_bin()
        .args(["--include-uid", "notanumber"])
        .output()
        .expect("Failed to execute panhandle");

    assert!(
        !output.status.success(),
        "non-numeric --include-uid should be rejected"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Invalid --include-uid"),
        "error should mention the invalid --include-uid value, got: {}",
        combined
    );
}

/// Test that a config-file include_uid entry that isn't numeric is rejected with the
/// same clean error as the CLI path, not a panic - the config file has no clap
/// value_parser to catch this before it reaches the same runtime parse.
#[test]
fn test_config_include_uid_non_numeric_rejected() {
    let config_path = "/tmp/panhandle_include_uid_non_numeric.yaml";
    fs::write(config_path, "include_uid: [\"not_a_uid\"]\n").unwrap();

    let output = panhandle_bin()
        .args(["--config", config_path])
        .output()
        .expect("Failed to execute panhandle");

    assert!(
        !output.status.success(),
        "a non-numeric config-file include_uid entry should be rejected, not panic"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Invalid --include-uid"),
        "error should mention the invalid value, got: {}",
        combined
    );
    assert!(
        !combined.to_lowercase().contains("panicked"),
        "should fail with a clean error, not a panic, got: {}",
        combined
    );
}

/// Test that more than the documented maximum of 10 --include-uid entries is rejected.
#[test]
fn test_include_uid_count_exceeded_rejected() {
    let uids: Vec<String> = (1..=11).map(|i| i.to_string()).collect();
    let output = panhandle_bin()
        .args(["--include-uid", &uids.join(",")])
        .output()
        .expect("Failed to execute panhandle");

    assert!(
        !output.status.success(),
        "more than 10 --include-uid entries should be rejected"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("UIDs") && combined.contains("exceeds"),
        "error should mention the UID count limit, got: {}",
        combined
    );
}

/// Test that more than the documented maximum of 20 --executables entries is rejected.
#[test]
fn test_executables_count_exceeded_rejected() {
    let paths: Vec<String> = (1..=21).map(|i| format!("/bin/p{i}")).collect();
    let output = panhandle_bin()
        .args(["--executables", &paths.join(",")])
        .output()
        .expect("Failed to execute panhandle");

    assert!(
        !output.status.success(),
        "more than 20 --executables entries should be rejected"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("executables") && combined.contains("exceeds"),
        "error should mention the executables count limit, got: {}",
        combined
    );
}

/// Test that providing both --comm-allow and --comm-deny is rejected rather than
/// silently preferring one.
#[test]
fn test_comm_allow_and_deny_both_rejected() {
    let output = panhandle_bin()
        .args([
            "--syscalls",
            "open",
            "--comm-allow",
            "bash",
            "--comm-deny",
            "zsh",
        ])
        .output()
        .expect("Failed to execute panhandle");

    assert!(
        !output.status.success(),
        "providing both --comm-allow and --comm-deny should be rejected"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Allow and deny"),
        "error should mention both lists were provided, got: {}",
        combined
    );
}

/// Test that a config-file comm_allow entry over the 15-byte length limit is rejected,
/// not silently truncated - clap's value_parser only validates CLI-sourced values, so
/// this specifically exercises the config-file path.
#[test]
fn test_config_comm_allow_length_exceeded_rejected() {
    let config_path = "/tmp/panhandle_comm_allow_too_long.yaml";
    fs::write(
        config_path,
        "syscalls: [\"execve\"]\ncomm_allow: [\"this_name_is_way_too_long_for_a_comm\"]\n",
    )
    .unwrap();

    let output = panhandle_bin()
        .args(["--config", config_path])
        .output()
        .expect("Failed to execute panhandle");

    assert!(
        !output.status.success(),
        "an over-length config-file comm_allow entry should be rejected"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Process name (comm) exceeds maximum length"),
        "error should mention the comm length limit, got: {}",
        combined
    );
}

/// Test that a config-file block_paths entry over the 255-byte length limit is
/// rejected with a clean error rather than panicking. Regression test for the fix
/// where only CLI-sourced block_paths were length-validated - a config-only value
/// reached an unguarded fixed-size array copy.
#[test]
fn test_config_block_paths_length_exceeded_rejected() {
    let config_path = "/tmp/panhandle_block_paths_too_long.yaml";
    let long_path = "a".repeat(300);
    fs::write(
        config_path,
        format!("syscalls: [\"open\"]\nblock_paths: [\"{long_path}\"]\n"),
    )
    .unwrap();

    let output = panhandle_bin()
        .args(["--config", config_path])
        .output()
        .expect("Failed to execute panhandle");

    assert!(
        !output.status.success(),
        "an over-length config-file block_paths entry should be rejected, not panic"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Path exceeds maximum length"),
        "error should mention the path length limit, got: {}",
        combined
    );
    assert!(
        !combined.to_lowercase().contains("panicked"),
        "should fail with a clean error, not a panic, got: {}",
        combined
    );
}

/// Test that more than the documented maximum of 64 --comm-allow entries is rejected,
/// even though clap's own num_args upper bound can't catch it for a single
/// comma-delimited argument (see test_raw_args_parse_comm_allow_count_boundary in
/// unit_tests.rs for the unit-level version of this same gap).
#[test]
fn test_comm_allow_count_exceeded_rejected() {
    let comms: Vec<String> = (1..=65).map(|i| format!("c{i}")).collect();
    let output = panhandle_bin()
        .args(["--syscalls", "open", "--comm-allow", &comms.join(",")])
        .output()
        .expect("Failed to execute panhandle");

    assert!(
        !output.status.success(),
        "more than 64 --comm-allow entries should be rejected"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("comm-allow/comm-deny entries") && combined.contains("exceeds"),
        "error should mention the comm count limit, got: {}",
        combined
    );
}

/// Test that more than the documented maximum of 64 --block-paths entries is rejected.
#[test]
fn test_block_paths_count_exceeded_rejected() {
    let paths: Vec<String> = (1..=65).map(|i| format!("/bin/p{i}")).collect();
    let output = panhandle_bin()
        .args(["--syscalls", "open", "--block-paths", &paths.join(",")])
        .output()
        .expect("Failed to execute panhandle");

    assert!(
        !output.status.success(),
        "more than 64 --block-paths entries should be rejected"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("block-paths entries") && combined.contains("exceeds"),
        "error should mention the block-paths count limit, got: {}",
        combined
    );
}

/// Test that --poll 0 is rejected by clap's range(1..) value_parser at the process
/// level, not just in a unit test of RawArgs::try_parse_from directly.
#[test]
fn test_poll_zero_rejected() {
    let output = panhandle_bin()
        .args(["--cpu", "--poll", "0"])
        .output()
        .expect("Failed to execute panhandle");

    assert!(!output.status.success(), "--poll 0 should be rejected");
}

/// Test that a negative --pid-list value is rejected by clap's u32 value_parser at
/// the process level.
#[test]
fn test_pid_list_negative_rejected() {
    let output = panhandle_bin()
        .args(["--cpu", "--pid-list", "-1"])
        .output()
        .expect("Failed to execute panhandle");

    assert!(
        !output.status.success(),
        "a negative --pid-list value should be rejected"
    );
}

/// Test that a config-file poll: 0 is rejected with a clean error rather than being
/// silently accepted. clap's range(1..) value_parser only applies to the CLI path
/// (test_raw_args_parse_poll_rejects_zero in unit_tests.rs), and a config-file 0 would
/// otherwise reach Duration::from_secs(0), spinning every enabled monitor loop with no
/// delay at all.
#[test]
fn test_config_poll_zero_rejected() {
    let config_path = "/tmp/panhandle_poll_zero.yaml";
    fs::write(config_path, "cpu: true\npoll: 0\n").unwrap();

    let output = panhandle_bin()
        .args(["--config", config_path])
        .output()
        .expect("Failed to execute panhandle");

    assert!(
        !output.status.success(),
        "a config-file poll: 0 should be rejected"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("--poll must be at least 1"),
        "error should mention the poll minimum, got: {}",
        combined
    );
}

/// Test that --exclude-min-uid greater than --exclude-max-uid is rejected rather than
/// silently producing an inverted (always-empty) exclude range, which would exclude
/// nothing instead of what the user presumably meant to exclude.
#[test]
fn test_exclude_uid_range_inverted_rejected() {
    let output = panhandle_bin()
        .args(["--exclude-min-uid", "500", "--exclude-max-uid", "100"])
        .output()
        .expect("Failed to execute panhandle");

    assert!(
        !output.status.success(),
        "exclude-min-uid > exclude-max-uid should be rejected"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("must not be greater than"),
        "error should mention the inverted range, got: {}",
        combined
    );
}

/// Test that the exclude-uid range check compares effective values (defaults applied),
/// not just explicitly-set ones: --exclude-min-uid above the default max (999) is just
/// as inverted as if both had been given explicitly.
#[test]
fn test_exclude_uid_min_above_default_max_rejected() {
    let output = panhandle_bin()
        .args(["--exclude-min-uid", "1000"])
        .output()
        .expect("Failed to execute panhandle");

    assert!(
        !output.status.success(),
        "exclude-min-uid above the default max should be rejected"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("must not be greater than"),
        "error should mention the inverted range, got: {}",
        combined
    );
}

/// Test that the same inverted-range check applies to a config-file-sourced range,
/// not just the CLI.
#[test]
fn test_config_exclude_uid_range_inverted_rejected() {
    let config_path = "/tmp/panhandle_exclude_uid_inverted.yaml";
    fs::write(config_path, "exclude_min_uid: 500\nexclude_max_uid: 100\n").unwrap();

    let output = panhandle_bin()
        .args(["--config", config_path])
        .output()
        .expect("Failed to execute panhandle");

    assert!(
        !output.status.success(),
        "a config-file inverted exclude-uid range should be rejected"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("must not be greater than"),
        "error should mention the inverted range, got: {}",
        combined
    );
}
