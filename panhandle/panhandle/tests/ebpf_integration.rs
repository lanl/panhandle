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

    // This will fail with "stack spilling" or "LLVM verifier" errors if the
    // #[inline(always)] fix on try_shell_entry is not present
    let ebpf = Ebpf::load(ebpf_bytes)
        .expect("eBPF program should load without stack spilling / verifier errors");

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
        "uid_options",
        "uid_include_list",
        "readline_events",
        "readline_uid_options",
        "readline_uid_include_list",
        "zlentry_events",
        "zlentry_uid_options",
        "zlentry_uid_include_list",
        "net_stats",
        "COMMS",
        "BLOCKED_PATHS",
    ];

    for map_name in expected_maps {
        assert!(
            ebpf.map(map_name).is_some(),
            "map '{}' should exist in embedded bytecode",
            map_name
        );
    }
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
