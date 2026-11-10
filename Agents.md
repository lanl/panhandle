# Panhandle - Agent Configuration

This file defines the AI agent configurations for the Panhandle project.

## Project Overview

Panhandle is an eBPF-based user activity monitoring tool for HPC
environments. It monitors execve syscalls and shell activity (bash/zsh)
using the Aya Rust library for eBPF.

## Agent Roles

### Primary Agent (Development)

- **Role**: Main development agent for Rust/ebpf development
- **Skills**: rust, cargo, ebpf, aya

### Documentation Agent

- **Role**: Documentation and markdown maintenance
- **Skills**: markdown, yaml, json

### Security Agent

- **Role**: Security auditing, dependency scanning
- **Skills**: cargo-audit, cargo-deny

## Available Skills

### Core Skills (Always Available)

- `opencode` - OpenCode framework assistance
- `report` - Issue/bug reporting

### Project-Specific Skills (Configured in opencode.json)

- `rust` - Rust development best practices
- `cargo` - Cargo workspace management
- `ebpf` - eBPF development with Rust
- `aya` - Aya library specific patterns

## Workflow Commands

### Development

```bash
# Run linting
./scripts/lint

# Update dependencies
./scripts/update

# Build
cd panhandle && cargo build --release

# Test
cd panhandle && cargo test

# Security check
cd panhandle && cargo deny check

# Verify every CLI/config option against a real kernel (requires sudo; not part of
# CI - see the script's own header). Run before a release, not on every change.
./scripts/verify-functionality
```

### Code Quality

- All Rust code must pass `cargo clippy -- -D warnings`
- Code must be formatted with `cargo fmt`
- No `unsafe` code without explicit justification
- All dependencies must pass `cargo deny check`

### Git Practices

- Commit messages follow conventional commits
- All changes must pass CI checks
- No Cargo.lock in gitignore for binaries (already handled)

## Environment

- **Rust**: 2024 edition, nightly toolchain
- **eBPF**: Aya 0.16+, kernel 5.8+ (RingBuf, always loaded); some features need
  more - see panhandle/README.md's Limitations section (5.7+ for --syscalls,
  6.0+ for --cgroup, 5.17+ for --socket, 5.5+ for --bound; both need CONFIG_DEBUG_INFO_BTF)
- **Build**: cargo, make
- **Testing**: cargo test, integration tests in `panhandle/tests/`; live CLI/config
  regression suite (needs root + real eBPF, not run by `cargo test` or CI) via
  `./scripts/verify-functionality`

## References

- [Aya GitHub](https://github.com/aya-rs/aya) - eBPF library
- [Panhandle Repo](https://github.com/lanl/panhandle) - Project repository
