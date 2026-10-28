# panhandle

## Description

A project to provide user activity monitoring for High Performance Computing
systems and clusters. The goal is to provide effective user activity
monitoring with minimal performance impact on the host running this service.

## Tools

This project uses [eBPF](https://ebpf.io/) to monitor events on a Linux host,
format and output those events as desired by the user. The output includes
options for http, syslog and file output as well as standard console output.
All outputs support text and JSON formatting.

This project is written in [Rust](https://www.rust-lang.org/) and uses the
[Aya](https://aya-rs.dev/) library (v0.16) to reduce dependencies and maximize
the ability of this program to run on a variety of systems.

## Components

The RPMs in the build artifacts provide:

1. The panhandle binary `/usr/sbin/panhandle`
2. The configuration file: `/opt/panhandle/panhandle.yaml`
3. The default systemd service to run panhandle:
   `/usr/lib/systemd/system/panhandle.service`
4. The man page at `/usr/share/man/man1/panhandle.1`
5. Logrotate configuration file: `/etc/logrotate.d/panhandle`

## Configuration & Implementation

1. Install the appropriate RPM for your Linux version.
2. If log monitoring by a SIEM or Splunk server is desired, please add the
   logfile `/var/log/panhandle/panhandle.log` to your monitored rsyslog file
   inputs.
3. Enable and start the panhandle systemd service with:
   `systemctl enable --now panhandle` or your configuration manager of choice.

## Development Environment Setup

### Rust Toolchain (Required)

```bash
# Install Rust toolchains
rustup toolchain install stable
rustup toolchain install nightly --component rust-src

# Install bpf-linker for eBPF compilation
cargo install bpf-linker

# For cross-compiling (optional)
rustup target add x86_64-unknown-linux-musl

# Or run the automated install script:
./scripts/rust_install.sh
```

### Node.js Tooling (Required for Linting)

```bash
# Install Node.js dependencies for markdown, YAML, JSON linting
npm install

# This installs:
# - markdownlint-cli (markdown linting)
# - jsonlint (JSON linting)
# yamllint is installed via pip: pip3 install --user yamllint
```

### Development Scripts

```bash
# Run all linting and tests (recommended before commits)
./scripts/lint

# Update all dependencies and regenerate SBOM
./scripts/update

# Check for unused/duplicate dependencies
./scripts/check-deps

# Build the project
cd panhandle && cargo build --release

# Run tests
cd panhandle && cargo test

# Security audit
cd panhandle && cargo deny check

# Generate and open documentation
cd panhandle && cargo doc --open

# Or use cargo-docs-rs to view docs.rs style docs locally
cargo docs-rs

# Install git hooks for automatic pre-commit/pre-push checks
./scripts/install-hooks

# Create a release (version bump, changelog, tag, build)
./scripts/release 1.0.25
```

## Releasability

`O5058 panhandle has been acknowledged by the NNSA for open-source release.`
