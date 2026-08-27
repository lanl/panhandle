//! Integration tests for config file loading and CLI argument merging.
//! Tests that work without requiring root or eBPF:
//! - Config parsing errors (fail before root check)
//! - --version, --help (exit before root check)

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
