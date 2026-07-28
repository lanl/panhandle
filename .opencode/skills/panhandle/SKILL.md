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

### Workspace Layout (Cargo Workspace)
```
panhandle/                          # Root workspace directory
├── Cargo.toml                      # Workspace manifest
├── panhandle/                      # Main binary crate
│   ├── Cargo.toml                  # Binary crate manifest
│   ├── src/                        # Main source code
│   │   ├── main.rs                 # Entry point (userspace)
│   │   ├── helpers.rs              # Event processing helpers
│   │   ├── input_configs.rs        # CLI argument parsing
│   │   ├── monitor_cpu_usage.rs    # CPU monitoring
│   │   ├── monitor_gpu_usage.rs    # GPU monitoring
│   │   ├── monitor_io_usage.rs     # I/O monitoring
│   │   ├── monitor_network_usage.rs # Network monitoring
│   │   ├── procfs_helpers.rs       # procfs-based monitoring
│   │   ├── unit_tests.rs           # Unit tests
│   │   └── lib.rs                   # Library exports
│   ├── build.rs                    # Build script
│   └── tests/                      # Integration tests
├── panhandle-common/               # Shared types and constants
│   ├── Cargo.toml                  # Common crate manifest
│   └── src/lib.rs                  # Common definitions (Readline, ExecveEvent, etc.)
├── panhandle-ebpf/                 # eBPF programs crate
│   ├── Cargo.toml                  # eBPF crate manifest
│   └── src/                        # eBPF source files
│       ├── main.rs                 # eBPF program entry
│       ├── cpu_usage.rs            # CPU monitoring eBPF
│       ├── readline.rs             # Shell command monitoring
│       ├── socket.rs               # Socket state monitoring
│       ├── vanilla_execve.rs       # Process execution monitoring
│       └── zlentry.rs              # Zsh command monitoring
├── files/                          # Packaging files
│   ├── panhandle.man               # Man page
│   ├── panhandle.service           # Systemd service file
│   ├── panhandle.yaml              # Default configuration
│   └── logrotate-panhandle         # Logrotate configuration
├── rpmbuild/                       # RPM build directory
├── scripts/                        # Utility scripts
│   ├── pre-install-rpm.sh         # Pre-install script
│   └── test_cpu_monitoring.sh      # Test script
├── test-configs/                   # Test configuration files
│   ├── all-bools.json
│   └── all-bools.yaml
└── CHANGELOG.md                    # Project changelog
```

### Aya v0.14.0 Specific Structure
- **Synchronous API**: Uses `PerfEventArray::open().for_each()` pattern
- **Generic Traits**: `EbpfEvent` trait for unified event processing
- **Map Types**: `PerfEventArray`, `HashMap`, `PerCpuArray` for different data
- **Program Types**: `UProbe`, `TracePoint`, `BtfTracePoint` for kernel hooks

## Build System

### Dependencies (Verified for Aya v0.14.0)
- **Rust**: nightly toolchain with `--component rust-src` for eBPF compilation
- **Stable Rust**: For standard compilation
- **Clang**: 12+ for BTF generation
- **LLVM**: 12+ for eBPF compilation
- **libelf**: Development package for ELF handling
- **bpf-linker**: `cargo install bpf-linker` (use `--no-default-features` on macOS)

### Build Process
1. **Standard Build**: `cargo build --release`
2. **Debug Build**: `cargo build`
3. **Cross-Compile**: `CC=${ARCH}-linux-musl-gcc cargo build --target ${ARCH}-unknown-linux-musl`
4. **BTF Generation**: Automatic with Aya library
5. **eBPF Compilation**: Automatic via build.rs using aya-build

### Build Features
- `user`: Enable userspace features (default for panhandle-common)
- All eBPF compilation handled automatically via Aya build system

### Current Version Compatibility
- **Aya**: v0.14.0 (synchronous PerfEventArray API)
- **aya-ebpf**: v0.2.1
- **aya-log**: v0.3.0 + aya-log-ebpf v0.2.0
- **Rust nightly**: Required for eBPF compilation

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

## Aya v0.14.0 Development Patterns

### Synchronous API Usage
After merging main and opencode-tailoring branches, panhandle now uses the **synchronous API** from Aya v0.14.0:

```rust
// ✅ CORRECT: Synchronous API (Aya v0.14.0)
use aya::maps::perf::{PerfEventArray, PerfEventArrayBuffer}; 

// Open perf event array and process synchronously
let mut events = PerfEventArray::try_from(ebpf.take_map("events").unwrap())?;
for cpu in online_cpus().unwrap() {
    let buf = events.open(cpu, Some(32))?;
    
    // Use for_each for synchronous processing
    buf.for_each(|event| {
        match event {
            PerfEvent::Sample { head, tail } => {
                let bytes = [head.to_vec(), tail.to_vec()].concat();
                // Process event data...
            }
            PerfEvent::Lost { count } => {
                error!("Lost {} events", count);
            }
        }
    });
}
```

### Generic Event Processing
The project now includes a unified `EbpfEvent` trait for generic event handling:

```rust
use panhandle::helpers::EbpfEvent;

pub trait EbpfEvent: Sized + Debug + Display {
    fn get_filter_key(&self) -> &str;    // For exclusion filtering
    fn get_command(&self) -> &str;       // Command/process name
    fn get_filename(&self) -> Option<&str>; // Execve filename
    fn get_args(&self) -> String;       // Command arguments
    fn get_uid(&self) -> u32;           // Process UID
    fn get_pid(&self) -> u32;           // Process PID
    fn get_tgid(&self) -> u32;          // Thread group ID
    fn get_gid(&self) -> u32;           // Group ID
}

// Implemented for Readline and ExecveEvent
impl EbpfEvent for Readline { /* ... */ }
impl EbpfEvent for ExecveEvent { /* ... */ }

// Generic event processor
pub fn consume_ebpf_map<T: EbpfEvent + Copy>(
    client: &Client,
    buf: PerfEventArrayBuffer<aya::maps::MapData>,
    // ... other parameters
) {
    // Generic event processing logic
}
```

### UProbe Attachment (Aya v0.14.0 API)
```rust
use aya::programs::{UProbe, uprobe::UProbeScope};

// ✅ CORRECT: New Aya v0.14.0 API
let program: &mut UProbe = ebpf.program_mut("readline").unwrap().try_into()?;
program.load()?;
program.attach(
    "readline_internal_teardown",  // Function to attach to
    file_path,                       // Path to the target binary
    UProbeScope::AllProcesses,       // Scope of attachment
)?;

// ❌ avoid: Old API (pre-v0.14.0)
// program.attach(Some("function"), offset, path, None)?;
```

### Common Aya v0.14.0 Patterns
1. **PerfEventArray** for synchronous event processing
2. **PerfEventArrayBuffer** returned from `.open()`
3. **`.for_each()`** method for event iteration
4. **No async/await** in basic event processing
5. **UProbeScope** enum for attachment scope

## Merge Conflict Resolution Patterns

### Handling Aya Version Differences
After the merge between main and opencode-tailoring branches:

**Problem**: Main branch used async API, opencode-tailoring used sync API  
**Solution**: Standardized on synchronous API for Aya v0.14.0 compatibility

**Key Changes:**
- Replace `AsyncPerfEventArray` with `PerfEventArray`
- Replace `.read_events().await` with `.for_each()`
- Update `attach()` method calls to use new signature
- Add Debug trait to types used in generic functions

### Import Fixes
```rust
// ✅ Correct imports for Aya v0.14.0
use aya::maps::perf::{PerfEvent, PerfEventArray, PerfEventArrayBuffer};
use aya::programs::{BtfTracePoint, KProbe, TracePoint, UProbe, uprobe::UProbeScope};
use aya::{Btf, Ebpf}; // Note: Bpf is deprecated, use Ebpf
```

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
