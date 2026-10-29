use crate::config::AppConfig;
use crate::ebpf_loader::{attach_lsm_hook, get_hash_map};
use crate::error::{PanhandleError, Result};
use aya::{Btf, maps::HashMap};
use panhandle_common::{ALLOW_LIST, DENY_LIST, LIST_MODE};

/// Setup syscall blocking (LSM hooks)
pub fn setup_syscall_blocking(ebpf: &mut aya::Ebpf, config: &AppConfig, btf: &Btf) -> Result<()> {
    if config.syscalls.is_empty() {
        return Ok(());
    }

    // Determine list mode (allow/deny)
    let (list_type, comms) = resolve_comm_list_mode(&config.comm_deny, &config.comm_allow)?;

    if list_type == 0 && !comms.is_empty() {
        eprintln!(
            "Syscall blocking enabled but no deny/allow comm list specified. No processes will be blocked."
        );
    }

    // Populate COMMS map
    let mut comm_map: HashMap<_, [u8; 16], u8> = get_hash_map(ebpf, "COMMS")?;

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
    let mut path_map: HashMap<_, [u8; 256], u8> = get_hash_map(ebpf, "BLOCKED_PATHS")?;

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

    // Attach LSM hooks based on syscalls
    for syscall in &config.syscalls {
        match syscall.as_str() {
            "open" | "openat" | "creat" => {
                attach_lsm_hook(ebpf, "file_open", "block_open", btf)?;
            }
            "execve" => {
                attach_lsm_hook(ebpf, "bprm_check_security", "block_execve", btf)?;
            }
            _ => {
                eprintln!("Warning: Unknown syscall for blocking: {}", syscall);
            }
        }
    }

    Ok(())
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
