use crate::error::{PanhandleError, Result};
use panhandle_common::*;

/// GlobalData configuration for panhandle (execve tracepoint)
/// Must match the eBPF-side PanhandleConfig struct exactly
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PanhandleConfig {
    pub shells: u32,
    pub exclude_min_uid: u32,
    pub exclude_max_uid: u32,
    pub include_enabled: u32,
    pub include_uids: [u32; UID_COUNT],
}

/// GlobalData configuration for shell (readline/zlentry uprobes)
/// Must match the eBPF-side ShellConfig struct exactly
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ShellConfig {
    pub shells: u32,
    pub exclude_min_uid: u32,
    pub exclude_max_uid: u32,
    pub include_enabled: u32,
    pub include_uids: [u32; UID_COUNT],
}

// Implement Aya's Pod trait for GlobalData
// Safety: These structs are #[repr(C)] with no padding, all fields are Pod types
unsafe impl aya::Pod for PanhandleConfig {}
unsafe impl aya::Pod for ShellConfig {}

/// Application configuration built from CLI args and config file
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub shells: bool,
    pub exclude_min_uid: u32,
    pub exclude_max_uid: u32,
    pub include_uids: Vec<u32>,
    pub executables: Vec<String>,
    pub block_paths: Vec<String>,
    pub comm_allow: Vec<String>,
    pub comm_deny: Vec<String>,
    pub syscalls: Vec<String>,
    pub pid_list: Vec<u32>,
    pub poll_seconds: u32,
    pub debug: bool,
    pub verbose: bool,
    pub json: bool,
    pub http: bool,
    pub syslog: bool,
    #[allow(dead_code)]
    pub syslog_address: String,
    #[allow(dead_code)]
    pub http_url: String,
    pub bash: bool,
    pub zsh: bool,
    pub cpu: bool,
    pub gpu: bool,
    pub network: bool,
    pub io: bool,
    pub memory: bool,
    pub memory_faults: Option<u64>,
    pub execve: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            shells: false,
            exclude_min_uid: MINUID,
            exclude_max_uid: MAXUID,
            include_uids: Vec::new(),
            executables: Vec::new(),
            block_paths: Vec::new(),
            comm_allow: Vec::new(),
            comm_deny: Vec::new(),
            syscalls: Vec::new(),
            pid_list: Vec::new(),
            poll_seconds: 30,
            debug: false,
            verbose: false,
            json: false,
            http: false,
            syslog: false,
            syslog_address: "udp://127.0.0.1:514".to_string(),
            http_url: "http://127.0.0.1:8080/events".to_string(),
            bash: false,
            zsh: false,
            cpu: false,
            gpu: false,
            network: false,
            io: false,
            memory: false,
            memory_faults: None,
            execve: false,
        }
    }
}

impl AppConfig {
    /// Build GlobalData configs from AppConfig
    pub fn build_global_configs(&self) -> (PanhandleConfig, ShellConfig) {
        let include_enabled = (!self.include_uids.is_empty()) as u32;

        let mut include_uids = [0u32; UID_COUNT];
        for (i, &uid) in self.include_uids.iter().enumerate() {
            if i < UID_COUNT {
                include_uids[i] = uid;
            }
        }

        let panhandle_config = PanhandleConfig {
            shells: self.shells as u32,
            exclude_min_uid: self.exclude_min_uid,
            exclude_max_uid: self.exclude_max_uid,
            include_enabled,
            include_uids,
        };

        let shell_config = ShellConfig {
            shells: self.shells as u32,
            exclude_min_uid: self.exclude_min_uid,
            exclude_max_uid: self.exclude_max_uid,
            include_enabled,
            include_uids,
        };

        (panhandle_config, shell_config)
    }

    /// Validate UID range
    pub fn validate_uid_range(&self) -> Result<()> {
        if self.exclude_min_uid > self.exclude_max_uid {
            return Err(PanhandleError::UidValidation(format!(
                "--exclude-min-uid ({}) must not be greater than --exclude-max-uid ({})",
                self.exclude_min_uid, self.exclude_max_uid
            )));
        }
        Ok(())
    }

    /// Validate include UIDs count
    pub fn validate_include_uids(&self) -> Result<()> {
        if self.include_uids.len() > UID_COUNT {
            return Err(PanhandleError::UidValidation(format!(
                "Too many include UIDs: {} (max {})",
                self.include_uids.len(),
                UID_COUNT
            )));
        }
        Ok(())
    }

    /// Validate executable count
    pub fn validate_executables(&self) -> Result<()> {
        if self.executables.len() > EXECUTABLE_COUNT {
            return Err(PanhandleError::InvalidArgument(format!(
                "Too many executables: {} (max {})",
                self.executables.len(),
                EXECUTABLE_COUNT
            )));
        }
        Ok(())
    }

    /// Validate block paths count
    pub fn validate_block_paths(&self) -> Result<()> {
        if self.block_paths.len() > MAX_BLOCKED_PATHS {
            return Err(PanhandleError::PathValidation(format!(
                "Too many block paths: {} (max {})",
                self.block_paths.len(),
                MAX_BLOCKED_PATHS
            )));
        }
        Ok(())
    }

    /// Validate comm lists
    pub fn validate_comm_lists(&self) -> Result<()> {
        // Check that both comm_allow and comm_deny are not both provided
        if !self.comm_allow.is_empty() && !self.comm_deny.is_empty() {
            return Err(PanhandleError::CommValidation(
                "Cannot specify both --comm-allow and --comm-deny".to_string(),
            ));
        }

        let total_comms = self.comm_allow.len() + self.comm_deny.len();
        if total_comms > MAX_BLOCKED_COMMS {
            return Err(PanhandleError::CommValidation(format!(
                "Too many comm entries: {} (max {})",
                total_comms, MAX_BLOCKED_COMMS
            )));
        }

        for comm in &self.comm_allow {
            if comm.len() > MAX_COMM_LENGTH {
                return Err(PanhandleError::CommValidation(format!(
                    "Comm '{}' exceeds max length {}",
                    comm, MAX_COMM_LENGTH
                )));
            }
        }
        for comm in &self.comm_deny {
            if comm.len() > MAX_COMM_LENGTH {
                return Err(PanhandleError::CommValidation(format!(
                    "Comm '{}' exceeds max length {}",
                    comm, MAX_COMM_LENGTH
                )));
            }
        }
        Ok(())
    }

    /// Validate block path lengths
    pub fn validate_block_path_lengths(&self) -> Result<()> {
        for path in &self.block_paths {
            if path.len() > MAX_PATH_LENGTH {
                return Err(PanhandleError::PathValidation(format!(
                    "Path '{}' exceeds max length {}",
                    path, MAX_PATH_LENGTH
                )));
            }
        }
        Ok(())
    }

    /// Validate all configuration
    pub fn validate_all(&self) -> Result<()> {
        self.validate_uid_range()?;
        self.validate_include_uids()?;
        self.validate_executables()?;
        self.validate_block_paths()?;
        self.validate_comm_lists()?;
        self.validate_block_path_lengths()?;
        self.validate_syscalls()?;

        if let Some(_poll) = (self.poll_seconds == 0).then_some(0) {
            return Err(PanhandleError::InvalidArgument(
                "--poll must be at least 1 (got 0)".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate syscalls are supported
    fn validate_syscalls(&self) -> Result<()> {
        for syscall in &self.syscalls {
            if !["open", "openat", "creat", "execve"].contains(&syscall.as_str()) {
                return Err(PanhandleError::InvalidArgument(format!(
                    "Invalid syscall '{}': supported: open, openat, creat, execve",
                    syscall
                )));
            }
        }
        Ok(())
    }

    /// Check if default execve monitor should run
    pub fn should_run_execve_monitor(&self) -> bool {
        self.execve
            || (!self.bash
                && !self.zsh
                && !self.cpu
                && !self.gpu
                && !self.network
                && !self.io
                && !self.memory
                && self.memory_faults.is_none()
                && self.syscalls.is_empty())
    }
}
