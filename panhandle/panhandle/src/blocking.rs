use crate::config::AppConfig;
use crate::ebpf_loader::{attach_lsm_cgroup_hook, attach_lsm_hook, get_hash_map_mut};
use crate::error::{PanhandleError, Result};
use aya::{Btf, maps::HashMap};
use panhandle_common::{ALLOW_LIST, DENY_LIST, LIST_MODE};

/// Returns true if the "bpf" LSM is present in the kernel's active LSM list
/// (`/sys/kernel/security/lsm`). A BPF_PROG_TYPE_LSM program can load and
/// attach successfully via BPF_RAW_TRACEPOINT_OPEN even when this is false
/// (that call only requires CONFIG_BPF_LSM=y), but the kernel's security
/// framework will never actually invoke the hook, so blocking silently does
/// nothing (applies to both system-wide and --cgroup-scoped blocking).
fn bpf_lsm_active() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|contents| lsm_list_contains_bpf(&contents))
        .unwrap_or(false)
}

fn lsm_list_contains_bpf(contents: &str) -> bool {
    contents.trim().split(',').any(|lsm| lsm == "bpf")
}

/// Setup syscall blocking (LSM hooks)
pub fn setup_syscall_blocking(ebpf: &mut aya::Ebpf, config: &AppConfig, btf: &Btf) -> Result<()> {
    if config.syscalls.is_empty() {
        return Ok(());
    }

    if !bpf_lsm_active() {
        eprintln!(
            "WARNING: --syscalls requested, but the \"bpf\" LSM is not in this kernel's active \
             LSM list (/sys/kernel/security/lsm). The BPF_PROG_TYPE_LSM program will load and \
             attach without error, but the kernel will never invoke it, so NO process will \
             actually be blocked. Add \"bpf\" to the kernel's lsm= boot parameter (or your \
             distro's CONFIG_LSM default list) and reboot to enable real enforcement. \
             Continuing to run with blocking effectively disabled."
        );
    }

    // Determine list mode (allow/deny)
    let (list_type, comms) = resolve_comm_list_mode(&config.comm_deny, &config.comm_allow)?;

    if list_type == 0 {
        eprintln!(
            "Syscall blocking enabled but no deny/allow comm list specified. No processes will be blocked."
        );
    }

    // Populate COMMS map
    let mut comm_map: HashMap<_, [u8; 16], u8> = get_hash_map_mut(ebpf, "COMMS")?;

    for comm_str in &comms {
        let mut comm = [0u8; 16];
        let bytes = comm_str.as_bytes();
        let len = bytes.len().min(15);
        comm[..len].copy_from_slice(&bytes[..len]);
        comm_map
            .insert(&comm, &list_type, 0)
            .map_err(PanhandleError::EbpfMap)?;
    }

    // Insert mode indicator
    if list_type != 0 {
        let mode_key = [LIST_MODE; 16];
        comm_map
            .insert(&mode_key, &list_type, 0)
            .map_err(PanhandleError::EbpfMap)?;
    }

    // Populate BLOCKED_PATHS map
    let mut path_map: HashMap<_, [u8; 256], u8> = get_hash_map_mut(ebpf, "BLOCKED_PATHS")?;

    if config.block_paths.is_empty() {
        let placeholder = [0u8; 256];
        path_map
            .insert(&placeholder, &0u8, 0)
            .map_err(PanhandleError::EbpfMap)?;
    } else {
        for path_str in &config.block_paths {
            let mut path = [0u8; 256];
            let bytes = path_str.as_bytes();
            let len = bytes.len().min(255);
            path[..len].copy_from_slice(&bytes[..len]);
            path_map
                .insert(&path, &1u8, 0)
                .map_err(PanhandleError::EbpfMap)?;
        }
    }

    // Attach LSM hooks based on syscalls - scoped to config.cgroup_path via the
    // *_cgroup program variants if given (--cgroup), system-wide otherwise.
    for (hook_name, program_name, cgroup_program_name) in hooks_for_syscalls(&config.syscalls) {
        match &config.cgroup_path {
            Some(cgroup_path) => {
                attach_lsm_cgroup_hook(ebpf, hook_name, cgroup_program_name, btf, cgroup_path)?;
                eprintln!(
                    "attached eBPF LSM cgroup hook '{}' -> {} (scoped to {})",
                    cgroup_program_name,
                    hook_name,
                    cgroup_path.display()
                );
            }
            None => {
                attach_lsm_hook(ebpf, hook_name, program_name, btf)?;
            }
        }
    }

    Ok(())
}

/// Map requested syscalls to the (hook, program, cgroup program) triples to attach,
/// once each: open/openat/creat all share the file_open hook, and aya refuses to load
/// the same program twice, so listing more than one of them must not attach twice.
fn hooks_for_syscalls(syscalls: &[String]) -> Vec<(&'static str, &'static str, &'static str)> {
    let mut hooks = Vec::new();
    for syscall in syscalls {
        let hook = match syscall.as_str() {
            "open" | "openat" | "creat" => ("file_open", "block_open", "block_open_cgroup"),
            "execve" => ("bprm_check_security", "block_execve", "block_execve_cgroup"),
            _ => {
                eprintln!("Warning: Unknown syscall for blocking: {}", syscall);
                continue;
            }
        };
        if !hooks.contains(&hook) {
            hooks.push(hook);
        }
    }
    hooks
}

/// Resolve comm list mode (allow vs deny)
fn resolve_comm_list_mode(
    comm_deny: &[String],
    comm_allow: &[String],
) -> Result<(u8, Vec<String>)> {
    if !comm_deny.is_empty() && !comm_allow.is_empty() {
        return Err(PanhandleError::Config(
            "Cannot specify both --comm-deny and --comm-allow".to_string(),
        ));
    }

    if !comm_deny.is_empty() {
        Ok((DENY_LIST, comm_deny.to_vec()))
    } else if !comm_allow.is_empty() {
        Ok((ALLOW_LIST, comm_allow.to_vec()))
    } else {
        Ok((0, Vec::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::{hooks_for_syscalls, lsm_list_contains_bpf};

    #[test]
    fn open_variants_attach_file_open_once() {
        let syscalls = ["open", "creat", "openat", "execve", "execve"].map(String::from);
        let hooks = hooks_for_syscalls(&syscalls);
        assert_eq!(
            hooks,
            vec![
                ("file_open", "block_open", "block_open_cgroup"),
                ("bprm_check_security", "block_execve", "block_execve_cgroup"),
            ]
        );
    }

    #[test]
    fn unknown_syscalls_are_skipped() {
        let syscalls = ["bogus", "execve"].map(String::from);
        assert_eq!(hooks_for_syscalls(&syscalls).len(), 1);
    }

    #[test]
    fn detects_bpf_present() {
        assert!(lsm_list_contains_bpf("lockdown,capability,bpf,yama\n"));
        assert!(lsm_list_contains_bpf("bpf"));
    }

    #[test]
    fn detects_bpf_absent() {
        assert!(!lsm_list_contains_bpf(
            "lockdown,capability,landlock,yama,apparmor,ima,evm\n"
        ));
        assert!(!lsm_list_contains_bpf(""));
    }

    #[test]
    fn does_not_match_substring() {
        assert!(!lsm_list_contains_bpf("ebpf,bpfilter"));
    }
}
