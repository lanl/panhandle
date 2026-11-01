use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PanhandleError {
    #[error("eBPF program load failed: {0}")]
    EbpfLoad(#[from] aya::EbpfError),

    #[error("eBPF program attach failed: {0}")]
    EbpfAttach(#[from] aya::programs::ProgramError),

    #[error("eBPF map error: {0}")]
    EbpfMap(#[from] aya::maps::MapError),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("YAML parsing error: {0}")]
    YamlParsing(#[from] serde_saphyr::Error),

    #[error("YAML serialization error: {0}")]
    YamlSerialization(#[from] serde_saphyr::ser::Error),

    #[error("HTTP request failed: {0}")]
    HttpRequest(#[from] reqwest::Error),

    #[error("HTTP error: {0}")]
    HttpStatus(String),

    #[error("Syslog error: {0}")]
    Syslog(#[from] syslog::Error),

    #[error("UID validation error: {0}")]
    UidValidation(String),

    #[error("Path validation error: {0}")]
    PathValidation(String),

    #[error("Comm validation error: {0}")]
    CommValidation(String),

    #[error("Missing required eBPF map: {0}")]
    MissingMap(String),

    #[error("Missing required eBPF program: {0}")]
    MissingProgram(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Kernel not supported: {0}")]
    #[allow(dead_code)]
    KernelNotSupported(String),

    #[error("BTF not available: {0}")]
    #[allow(dead_code)]
    BtfUnavailable(String),

    #[error("Procfs error: {0}")]
    Procfs(#[from] procfs::ProcError),

    #[error("Logger error: {0}")]
    Logger(#[from] log::SetLoggerError),

    #[error("Async FD error: {0}")]
    AsyncFd(String),

    #[error("Internal error: {0}")]
    #[allow(dead_code)]
    Internal(String),
}

// Manual PartialEq implementation that compares variants and string contents
// (for variants wrapping types that don't implement PartialEq, we only compare the variant)
impl PartialEq for PanhandleError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Config(a), Self::Config(b)) => a == b,
            (Self::InvalidArgument(a), Self::InvalidArgument(b)) => a == b,
            (Self::HttpStatus(a), Self::HttpStatus(b)) => a == b,
            (Self::UidValidation(a), Self::UidValidation(b)) => a == b,
            (Self::PathValidation(a), Self::PathValidation(b)) => a == b,
            (Self::CommValidation(a), Self::CommValidation(b)) => a == b,
            (Self::MissingMap(a), Self::MissingMap(b)) => a == b,
            (Self::MissingProgram(a), Self::MissingProgram(b)) => a == b,
            (Self::PermissionDenied(a), Self::PermissionDenied(b)) => a == b,
            (Self::KernelNotSupported(a), Self::KernelNotSupported(b)) => a == b,
            (Self::BtfUnavailable(a), Self::BtfUnavailable(b)) => a == b,
            (Self::AsyncFd(a), Self::AsyncFd(b)) => a == b,
            (Self::Internal(a), Self::Internal(b)) => a == b,
            // For variants wrapping non-PartialEq types, only compare the variant
            (Self::EbpfLoad(_), Self::EbpfLoad(_)) => true,
            (Self::EbpfAttach(_), Self::EbpfAttach(_)) => true,
            (Self::EbpfMap(_), Self::EbpfMap(_)) => true,
            (Self::Io(_), Self::Io(_)) => true,
            (Self::Serialization(_), Self::Serialization(_)) => true,
            (Self::YamlParsing(_), Self::YamlParsing(_)) => true,
            (Self::YamlSerialization(_), Self::YamlSerialization(_)) => true,
            (Self::HttpRequest(_), Self::HttpRequest(_)) => true,
            (Self::Syslog(_), Self::Syslog(_)) => true,
            (Self::Procfs(_), Self::Procfs(_)) => true,
            (Self::Logger(_), Self::Logger(_)) => true,
            _ => false,
        }
    }
}

pub type Result<T> = std::result::Result<T, PanhandleError>;

impl PanhandleError {
    #[allow(dead_code)]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    #[allow(dead_code)]
    pub fn invalid_arg(msg: impl Into<String>) -> Self {
        Self::InvalidArgument(msg.into())
    }

    #[allow(dead_code)]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}
