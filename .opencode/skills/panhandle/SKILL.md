---
name: panhandle
description: Use when working on the panhandle project specifically. Covers project conventions, build system, testing, and deployment patterns for the eBPF user activity monitoring system.
license: MIT
---

# Panhandle Project Skill

## When to Use
Use this skill when:
- Working on the panhandle codebase
- Following panhandle project conventions
- Building, testing, or deploying panhandle
- Understanding panhandle architecture and design decisions
- Contributing to the panhandle project

## Project Overview

### Purpose
Panhandle provides **user activity monitoring for High Performance Computing systems** with:
- **Minimal Performance Impact**: Designed to add <1% overhead to monitored systems
- **eBPF Technology**: Uses eBPF for efficient kernel-level monitoring
- **Aya Library**: Rust-based eBPF development framework
- **Multiple Outputs**: Supports HTTP, syslog, file, and console output
- **Flexible Formatting**: JSON and text output formats

### Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    User Space (Rust)                        │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │
│  │   Main      │───▶│   Output    │───▶│   HTTP/Syslog   │  │
│  │   Process   │    │   Formatter │    │   File/Console   │  │
│  └─────────────┘    └─────────────┘    └─────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                     ▲          ▲          ▲
                     │          │          │
┌─────────────────────────────────────────────────────────────┐
│                   Kernel Space (eBPF)                      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │
│  │  Tracepoint  │    │   XDP/TC     │    │  Socket Filter  │  │
│  │   Programs   │    │   Programs   │    │   Programs      │  │
│  └─────────────┘    └─────────────┘    └─────────────────┘  │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                     eBPF Maps                           │  │
│  │  (HashMap, Array, PerCpuArray, RingBuf, etc.)            │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

### Directory Layout
```
panhandle/
├── src/                    # Main source code
│   ├── main.rs             # Userspace main entry point
│   ├── ebpf/               # eBPF program definitions
│   │   ├── mod.rs          # eBPF module exports
│   │   ├── programs.rs     # eBPF program implementations
│   │   └── maps.rs         # eBPF map definitions
│   ├── userspace/          # Userspace components
│   │   ├── output/         # Output handlers
│   │   │   ├── http.rs     # HTTP output
│   │   │   ├── syslog.rs   # Syslog output
│   │   │   ├── file.rs     # File output
│   │   │   └── console.rs  # Console output
│   │   ├── config.rs       # Configuration parsing
│   │   └── event.rs        # Event processing
│   └── error.rs            # Error types and handling
├── xtask/                  # Build tasks and utilities
│   └── main.rs             # Custom build tasks
├── files/                  # Packaging files
│   ├── panhandle.service   # Systemd service file
│   ├── panhandle.yaml      # Default configuration
│   └── panhandle.log       # Example log file
├── build.rs                # Cargo build script
├── Cargo.toml              # Project dependencies
└── README.md               # Project documentation
```

## Build System

### Dependencies
- **Rust**: 1.70+ with nightly features for eBPF
- **Clang**: For BTF generation
- **LLVM**: For eBPF compilation
- **libelf**: For ELF file handling
- **zlib**: For compression (if needed)

### Build Process
1. **Standard Build**: `cargo build --release`
2. **Debug Build**: `cargo build`
3. **Cross-Compile**: Use `--target` flag for different architectures
4. **BTF Generation**: Automatic with Aya library

### Build Features
- `bpf`: Enable eBPF program compilation (default)
- `userspace`: Enable userspace components (default)
- `static`: Build static binaries

### Build Troubleshooting
- **Missing LLVM**: Install llvm-tools-preview
- **BTF Issues**: Ensure kernel has BTF enabled
- **Permission Errors**: Use `sudo` or appropriate capabilities
- **Verifier Errors**: Check eBPF program for safety violations

## Development Workflow

### Setting Up
1. Clone the repository: `git clone <repo-url>`
2. Install dependencies: `cargo fetch`
3. Build the project: `cargo build`
4. Run tests: `cargo test`

### Common Tasks
- **Add New eBPF Program**: Add to `src/ebpf/programs.rs`
- **Add New Output**: Add to `src/userspace/output/`
- **Update Configuration**: Modify `panhandle.yaml`
- **Build RPM**: Use `rpmbuild` with provided spec file

### Coding Conventions
- **Rust Style**: Follow Rust style guidelines (rustfmt)
- **Error Handling**: Use `thiserror` or `anyhow` for errors
- **Logging**: Use `tracing` crate for logging
- **Documentation**: Document all public APIs
- **Testing**: Add tests for new functionality

## Testing

### Test Structure
- **Unit Tests**: For individual functions and modules
- **Integration Tests**: For component interactions
- **eBPF Tests**: For eBPF program functionality
- **End-to-End Tests**: For complete monitoring workflows

### Running Tests
- **All Tests**: `cargo test`
- **Specific Test**: `cargo test <test-name>`
- **eBPF Tests**: `cargo test --features bpf`
- **Release Tests**: `cargo test --release`

### Test Coverage
- Aim for 80%+ code coverage
- Focus on critical paths and error handling
- Test edge cases and error conditions
- Include performance tests where applicable

## Deployment

### Installation Methods
1. **RPM Package**: Recommended for RHEL-based systems
2. **Manual Install**: Copy binary and configuration files
3. **Container**: Docker container for development/testing
4. **From Source**: `cargo install --path .`

### Systemd Service
- **Service File**: `/usr/lib/systemd/system/panhandle.service`
- **Configuration**: `/opt/panhandle/panhandle.yaml`
- **Logs**: `/var/log/panhandle/panhandle.log`
- **Commands**:
  - Start: `systemctl start panhandle`
  - Stop: `systemctl stop panhandle`
  - Status: `systemctl status panhandle`
  - Enable: `systemctl enable panhandle`

### Configuration
- **Main Config**: `/opt/panhandle/panhandle.yaml`
- **Environment Variables**: `PANHANDLE_*` for runtime overrides
- **Command Line**: Flags override configuration file

## Monitoring and Maintenance

### Monitoring Panhandle
- **Service Status**: `systemctl status panhandle`
- **Logs**: `journalctl -u panhandle -f`
- **Metrics**: Check output destinations for data
- **Performance**: Monitor system resource usage

### Common Issues
- **Service Fails to Start**: Check configuration and permissions
- **No Events**: Verify eBPF program loading and attachment
- **Performance Issues**: Check for high CPU/memory usage
- **Output Issues**: Verify output destination connectivity

### Upgrading
1. Stop the service: `systemctl stop panhandle`
2. Install new version: `rpm -U panhandle-*.rpm`
3. Restart the service: `systemctl start panhandle`
4. Verify functionality: Check logs and outputs

## Contributing

### Getting Started
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Update documentation
6. Submit a pull request

### Pull Request Guidelines
- Follow coding conventions
- Include tests and documentation
- Keep commits atomic and well-described
- Reference related issues
- Include performance considerations

### Code Review Process
- All changes require review
- Focus on correctness, safety, and performance
- Address all review comments
- Test thoroughly before merging

## Resources

### Documentation
- [README](../README.md) - Project overview
- [Architecture](docs/architecture.md) - System architecture
- [Configuration](docs/configuration.md) - Configuration guide
- [Development](docs/development.md) - Development guide

### External Resources
- [Aya Documentation](https://aya-rs.dev/)
- [eBPF Documentation](https://ebpf.io/)
- [Rust Documentation](https://doc.rust-lang.org/)
- [Linux Kernel Documentation](https://www.kernel.org/doc/)

### Community
- GitHub Issues and Discussions
- Rust eBPF Working Group
- Aya Discord/Slack channels
