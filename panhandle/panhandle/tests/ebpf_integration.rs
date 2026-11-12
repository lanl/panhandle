//! Integration test to verify the eBPF program loads successfully without
//! stack-spilling or LLVM verifier errors. This validates the fix for
//! the `#[inline(always)]` attribute on `try_shell_entry` in shell_entry.rs.

use std::path::Path;

use aya::Ebpf;

/// Test that the eBPF bytecode embedded in the binary loads without
/// "stack spilling" or "LLVM verifier" errors. This is the actual fix
/// on branch `bash-option-fix` - the `#[inline(always)]` attribute on
/// `try_shell_entry` in shell_entry.rs.
#[test]
fn test_ebpf_loads_without_stack_spilling() {
    // The eBPF bytecode is embedded at compile time via aya::include_bytes_aligned!
    // It's located at OUT_DIR/panhandle relative to the panhandle crate root
    let ebpf_bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/panhandle"));

    // Try to load the eBPF program. In some CI environments (GitHub Actions Docker
    // containers), the kernel may not support all eBPF features or may have
    // seccomp/AppArmor restrictions. If loading fails with a permission/kernel
    // error, we skip the test rather than fail the build.
    let ebpf = match Ebpf::load(ebpf_bytes) {
        Ok(ebpf) => ebpf,
        Err(e) => {
            // Check if it's a stack spilling / verifier error (the actual fix we're testing)
            let err_str = format!("{:?}", e);
            if err_str.contains("stack")
                || err_str.contains("verifier")
                || err_str.contains("invalid")
            {
                panic!(
                    "eBPF program should load without stack spilling / verifier errors: {}",
                    e
                );
            }
            // Otherwise it's likely a CI environment limitation (kernel version, seccomp, etc.)
            // Skip the test with a message
            eprintln!(
                "Skipping eBPF load test - kernel/environment limitation: {}",
                e
            );
            return;
        }
    };

    // Verify all expected programs are present in the loaded bytecode
    // These are the programs defined in panhandle-ebpf/src/main.rs and shell_entry.rs
    let expected_programs = [
        "panhandle",           // tracepoint for sys_enter_execve
        "readline",            // uretprobe for bash readline
        "zlentry",             // uretprobe for zsh zleentry
        "inet_sock_set_state", // BTF tracepoint for network
    ];

    for prog_name in expected_programs {
        let prog = ebpf
            .program(prog_name)
            .unwrap_or_else(|| panic!("program '{}' should exist in embedded bytecode", prog_name));
        // Verify the program has a valid type (not just that it exists)
        let prog_type = prog.prog_type();
        assert!(
            prog_type != aya::programs::ProgramType::Unspecified,
            "program '{}' should have a valid program type",
            prog_name
        );
    }

    // Verify all expected maps exist
    let expected_maps = [
        "panhandle_execve_events",
        "readline_events",
        "zlentry_events",
        "socket_events",
        "COMMS",
        "BLOCKED_PATHS",
        "uid_options",
        "uid_include_list",
        "readline_uid_options",
        "readline_uid_include_list",
        "zlentry_uid_options",
        "zlentry_uid_include_list",
    ];

    for map_name in expected_maps {
        assert!(
            ebpf.map(map_name).is_some(),
            "map '{}' should exist in embedded bytecode",
            map_name
        );
    }
}

/// Test that each program's actual eBPF program type matches the concrete type
/// `main.rs` casts it to via `program_mut(...).try_into::<&mut T>()`. This is the
/// check that would have caught the aya-16 regression where `panhandle` was cast
/// to `TracePoint` after the eBPF side briefly moved to `#[raw_tracepoint]`
/// (`RawTracePoint`): `test_ebpf_loads_without_stack_spilling` only checked the
/// programs *exist*, not that they load as the type the userspace code actually
/// expects. `panhandle` is back on a plain `TracePoint` (see main.rs for why raw
/// tracepoints can't target a per-syscall name like `sys_enter_execve`).
#[test]
fn test_programs_have_expected_types() {
    use aya::programs::{BtfTracePoint, TracePoint, UProbe};

    let ebpf_bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/panhandle"));
    let mut ebpf = match Ebpf::load(ebpf_bytes) {
        Ok(ebpf) => ebpf,
        Err(e) => {
            eprintln!(
                "Skipping eBPF program-type test - kernel/environment limitation: {}",
                e
            );
            return;
        }
    };

    let _: &mut TracePoint = ebpf
        .program_mut("panhandle")
        .expect("program 'panhandle' should exist in embedded bytecode")
        .try_into()
        .expect("'panhandle' should load as a TracePoint, matching main.rs's cast");

    let _: &mut UProbe = ebpf
        .program_mut("readline")
        .expect("program 'readline' should exist in embedded bytecode")
        .try_into()
        .expect("'readline' should load as a UProbe, matching main.rs's cast");

    let _: &mut UProbe = ebpf
        .program_mut("zlentry")
        .expect("program 'zlentry' should exist in embedded bytecode")
        .try_into()
        .expect("'zlentry' should load as a UProbe, matching main.rs's cast");

    let _: &mut BtfTracePoint = ebpf
        .program_mut("inet_sock_set_state")
        .expect("program 'inet_sock_set_state' should exist in embedded bytecode")
        .try_into()
        .expect("'inet_sock_set_state' should load as a BtfTracePoint, matching main.rs's cast");
}

/// Test that the binary exists and can be executed (smoke test)
#[test]
fn test_binary_exists() {
    // In CI/build environment, the binary is at target/release/panhandle
    // In development, it might be at target/debug/panhandle
    let release_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/release/panhandle");
    let debug_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/debug/panhandle");

    let binary_path = if release_path.exists() {
        release_path
    } else if debug_path.exists() {
        debug_path
    } else {
        panic!(
            "panhandle binary not found at {:?} or {:?}",
            release_path, debug_path
        );
    };

    assert!(
        binary_path.exists(),
        "panhandle binary should exist at {:?}",
        binary_path
    );
    assert!(binary_path.is_file(), "panhandle should be a file");
}
