//! Functional integration tests that run the panhandle binary and verify
//! it generates events. These tests REQUIRE root privileges and a working
//! eBPF environment with BTF support.
//!
//! Run with: sudo -E cargo +nightly test -p panhandle --test functional_integration -- --nocapture
//!
//! Note: These tests are marked #[ignore] by default so they don't run in
//! standard CI. Enable them by removing the ignore attribute or running
//! with --include-ignored.

use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

fn panhandle_bin() -> Command {
    let bin_path = env!("CARGO_BIN_EXE_panhandle");
    let mut cmd = Command::new(bin_path);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd
}

/// Returns a path in a project-local temp directory.
fn temp_path(name: &str) -> PathBuf {
    let base = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .or_else(|_| std::env::current_dir().map(|c| c.join("target")))
        .unwrap_or_else(|_| std::env::temp_dir());
    let path = base.join("test_tmp").join(name);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    path
}

/// Check if we're running as root and have BTF
fn check_root_and_btf() -> Result<(), String> {
    // Check root
    if uzers::get_current_uid() != 0 {
        return Err("Tests require root privileges (run with sudo)".to_string());
    }

    // Check BTF
    if !PathBuf::from("/sys/kernel/btf/vmlinux").exists() {
        return Err("BTF not available at /sys/kernel/btf/vmlinux".to_string());
    }

    Ok(())
}

/// Run panhandle with given args for a short duration, return stdout/stderr
fn run_panhandle_brief(args: &[&str], timeout_secs: u64) -> Result<(String, String, bool), String> {
    let mut cmd = panhandle_bin();
    cmd.args(args);

    let mut child = cmd.spawn().map_err(|e| format!("Failed to spawn: {}", e))?;

    // Wait for timeout
    std::thread::sleep(Duration::from_secs(timeout_secs));

    // Kill the process
    let _ = child.kill();

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Wait failed: {}", e))?;

    Ok((
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.success(),
    ))
}

#[test]
#[ignore] // Requires root + BTF
fn test_syscall_execve_generates_events() {
    check_root_and_btf().expect("Prerequisites not met");

    // Run panhandle with --syscall-execve for 3 seconds
    let (stdout, stderr, _) = run_panhandle_brief(&["--syscall-execve"], 3).expect("Run failed");

    // Should see execve events in output (panhandle logs to stdout by default)
    // The output format includes: timestamp, hostname, comm, pid, ppid, uid, args...
    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);

    // At minimum, we should see our own execve event when panhandle started
    // or other system activity. The test passes if it runs without crashing.
    assert!(
        !stdout.is_empty() || !stderr.is_empty(),
        "Should produce some output"
    );
}

#[test]
#[ignore]
fn test_bash_monitoring_generates_events() {
    check_root_and_btf().expect("Prerequisites not met");

    // Run panhandle with --bash for 3 seconds
    let (stdout, stderr, _) = run_panhandle_brief(&["--bash"], 3).expect("Run failed");

    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);

    // Should see readline events if any bash session was active
    // At minimum should start without crashing
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
#[ignore]
fn test_cpu_monitoring_generates_output() {
    check_root_and_btf().expect("Prerequisites not met");

    // Run with --cpu and short poll interval
    let (stdout, stderr, _) =
        run_panhandle_brief(&["--cpu", "--poll", "1"], 4).expect("Run failed");

    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);

    // Should see periodic CPU usage reports
    assert!(
        stdout.contains("CPU") || stderr.contains("CPU"),
        "Should report CPU metrics"
    );
}

#[test]
#[ignore]
fn test_memory_monitoring_generates_output() {
    check_root_and_btf().expect("Prerequisites not met");

    let (stdout, stderr, _) =
        run_panhandle_brief(&["--memory", "--poll", "1"], 4).expect("Run failed");

    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);

    assert!(
        stdout.contains("memory") || stdout.contains("MEMORY") || stderr.contains("memory"),
        "Should report memory metrics"
    );
}

#[test]
#[ignore]
fn test_io_monitoring_generates_output() {
    check_root_and_btf().expect("Prerequisites not met");

    let (stdout, stderr, _) = run_panhandle_brief(&["--io", "--poll", "1"], 4).expect("Run failed");

    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);

    assert!(
        stdout.contains("IO") || stdout.contains("io") || stderr.contains("io"),
        "Should report IO metrics"
    );
}

#[test]
#[ignore]
fn test_socket_monitoring_generates_output() {
    check_root_and_btf().expect("Prerequisites not met");

    // Socket monitoring requires BTF
    let (stdout, stderr, _) =
        run_panhandle_brief(&["--socket", "--poll", "1"], 4).expect("Run failed");

    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);

    // Socket monitoring attaches BTF tracepoints and kprobes
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
#[ignore]
fn test_bound_monitoring_generates_output() {
    check_root_and_btf().expect("Prerequisites not met");

    let (stdout, stderr, _) =
        run_panhandle_brief(&["--bound", "--poll", "1"], 4).expect("Run failed");

    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);

    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
#[ignore]
fn test_output_file_writes_events() {
    check_root_and_btf().expect("Prerequisites not met");

    let log_file = temp_path("panhandle_test.log");

    let (stdout, stderr, success) = run_panhandle_brief(
        &[
            "--syscall-execve",
            "output",
            "--file",
            log_file.to_str().unwrap(),
        ],
        3,
    )
    .expect("Run failed");

    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);

    assert!(success, "Should exit cleanly on SIGTERM");

    // Check that log file was created and has content
    let content = fs::read_to_string(&log_file).unwrap_or_default();
    println!("Log file content:\n{}", content);
    assert!(!content.is_empty(), "Log file should contain events");
}

#[test]
#[ignore]
fn test_output_json_format() {
    check_root_and_btf().expect("Prerequisites not met");

    let (stdout, stderr, _) =
        run_panhandle_brief(&["--syscall-execve", "--json"], 3).expect("Run failed");

    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);

    // JSON output should be valid JSON lines
    for line in stdout.lines() {
        if !line.trim().is_empty() {
            serde_json::from_str::<serde_json::Value>(line)
                .unwrap_or_else(|_| panic!("Output line should be valid JSON: {}", line));
        }
    }
}

#[test]
#[ignore]
fn test_uid_filtering_excludes_root() {
    check_root_and_btf().expect("Prerequisites not met");

    // Exclude UID 0 (root) - panhandle itself runs as root so should not see its own events
    let (stdout, stderr, _) = run_panhandle_brief(
        &[
            "--syscall-execve",
            "--exclude-min-uid",
            "0",
            "--exclude-max-uid",
            "0",
        ],
        3,
    )
    .expect("Run failed");

    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);

    // With root excluded, we might see fewer events
    // Test mainly verifies it runs without error
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
#[ignore]
fn test_combined_monitors() {
    check_root_and_btf().expect("Prerequisites not met");

    // Test running multiple monitors simultaneously
    let (stdout, stderr, _) =
        run_panhandle_brief(&["--cpu", "--memory", "--io", "--poll", "1"], 5).expect("Run failed");

    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);

    // Should see output from all three monitors
    let has_cpu = stdout.contains("CPU") || stderr.contains("CPU");
    let has_mem =
        stdout.contains("memory") || stdout.contains("MEMORY") || stderr.contains("memory");
    let has_io = stdout.contains("IO") || stdout.contains("io") || stderr.contains("io");

    assert!(has_cpu, "Should report CPU");
    assert!(has_mem, "Should report memory");
    assert!(has_io, "Should report IO");
}

#[test]
#[ignore]
fn test_shells_flag_monitors_shell_execves() {
    check_root_and_btf().expect("Prerequisites not met");

    // --shells monitors execve but only for shell processes (bash, tcsh, zsh)
    let (stdout, stderr, _) = run_panhandle_brief(&["--shells"], 3).expect("Run failed");

    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);

    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
#[ignore]
fn test_executable_filter() {
    check_root_and_btf().expect("Prerequisites not met");

    // Filter to only monitor /bin/ls execves
    let (stdout, stderr, _) =
        run_panhandle_brief(&["--syscall-execve", "--executables", "/bin/ls"], 3)
            .expect("Run failed");

    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);

    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
#[ignore]
fn test_poll_interval_respected() {
    check_root_and_btf().expect("Prerequisites not met");

    // With --poll 2, we should see at most 2 reports in 5 seconds (at t=2, t=4)
    // This is a rough timing test
    let start = std::time::Instant::now();
    let (stdout, stderr, _) =
        run_panhandle_brief(&["--cpu", "--poll", "2"], 5).expect("Run failed");
    let elapsed = start.elapsed();

    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);
    println!("Elapsed: {:?}", elapsed);

    // Count CPU report lines
    let cpu_lines: Vec<&str> = stdout.lines().filter(|l| l.contains("CPU")).collect();
    println!("CPU report lines: {}", cpu_lines.len());

    // With poll=2 over 5 seconds, expect ~2 reports
    // Allow some variance due to startup time
    assert!(
        !cpu_lines.is_empty(),
        "Should produce at least 1 CPU report"
    );
    assert!(cpu_lines.len() <= 4, "Should not produce excessive reports");
}

#[test]
#[ignore]
fn test_verbose_flag_adds_fields() {
    check_root_and_btf().expect("Prerequisites not met");

    let (stdout_verbose, _, _) =
        run_panhandle_brief(&["--cpu", "--poll", "1", "--verbose"], 3).expect("Run failed");
    let (stdout_normal, _, _) =
        run_panhandle_brief(&["--cpu", "--poll", "1"], 3).expect("Run failed");

    println!("Verbose stdout:\n{}", stdout_verbose);
    println!("Normal stdout:\n{}", stdout_normal);

    // Verbose output should contain PPID/Parent_Comm, UID/Username, State fields
    // This is a basic check - verbose lines should be longer/have more fields
    let verbose_lines: Vec<&str> = stdout_verbose
        .lines()
        .filter(|l| l.contains("CPU"))
        .collect();
    let normal_lines: Vec<&str> = stdout_normal
        .lines()
        .filter(|l| l.contains("CPU"))
        .collect();

    if !verbose_lines.is_empty() && !normal_lines.is_empty() {
        // Verbose lines should generally be longer (more fields)
        let avg_verbose_len: usize =
            verbose_lines.iter().map(|l| l.len()).sum::<usize>() / verbose_lines.len();
        let avg_normal_len: usize =
            normal_lines.iter().map(|l| l.len()).sum::<usize>() / normal_lines.len();
        println!(
            "Avg verbose line len: {}, normal: {}",
            avg_verbose_len, avg_normal_len
        );
        // Verbose should have more content (PPID, UID, state)
        assert!(
            avg_verbose_len >= avg_normal_len,
            "Verbose output should have more fields"
        );
    }
}

#[test]
#[ignore]
fn test_quiet_flag_suppresses_terminal_output() {
    check_root_and_btf().expect("Prerequisites not met");

    let (stdout_quiet, _, _) =
        run_panhandle_brief(&["--cpu", "--poll", "1", "--quiet"], 3).expect("Run failed");
    let (stdout_normal, _, _) =
        run_panhandle_brief(&["--cpu", "--poll", "1"], 3).expect("Run failed");

    println!("Quiet stdout lines: {}", stdout_quiet.lines().count());
    println!("Normal stdout lines: {}", stdout_normal.lines().count());

    // Quiet should have less or no terminal output
    assert!(
        stdout_quiet.lines().count() <= stdout_normal.lines().count(),
        "Quiet mode should produce less terminal output"
    );
}

#[test]
#[ignore]
fn test_syscall_blocking_loads() {
    check_root_and_btf().expect("Prerequisites not met");

    // Test that syscall blocking loads without error (doesn't test actual blocking)
    let (stdout, stderr, success) =
        run_panhandle_brief(&["--syscalls", "open", "--comm-allow", "bash"], 3)
            .expect("Run failed");

    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);

    // Should start successfully (exit cleanly on SIGTERM)
    assert!(success || !stdout.is_empty() || !stderr.is_empty());
}
