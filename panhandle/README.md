# panhandle

## How to set up Development Environment

### Rust Toolchain (Required)

1. Stable rust toolchains: `rustup toolchain install stable`
2. bpf-linker (using pre-built binary):
   - Option 1: `cargo install cargo-binstall && cargo binstall bpf-linker` (recommended)
   - Option 2: Manual download from GitHub releases (if cargo-binstall unavailable)
3. Nightly rust toolchains:
   `rustup toolchain install nightly --component rust-src`
4. Optional: (if cross-compiling) rustup target:
   `rustup target add ${ARCH}-unknown-linux-musl`
5. Optional: (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
6. Optional: (if cross-compiling) C toolchain: (e.g.)
   [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
7. Sudo for your user is required.

### Development Tools (Optional)

```bash
# From the panhandle directory
cargo install cargo-audit cargo-outdated cargo-machete cargo-deny cargo-sbom cargo-docs-rs cargo-tarpaulin

# Or run the automated install script from repo root:
./scripts/rust_install.sh
```

### Node.js Tooling (Required for Linting)

```bash
# From the repository root
npm install

# This installs:
# - markdownlint-cli (markdown linting)
# - jsonlint (JSON linting)
# yamllint is installed via pip: pip3 install --user yamllint
```

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release'
```

Cargo build scripts are used to automatically build the eBPF bytecode
correctly and include it in the program.

## Development Scripts

```bash
# From the repository root

# Run all linting and tests (recommended before commits)
./scripts/lint

# Update all dependencies and regenerate SBOM
./scripts/update

# Check for unused/duplicate dependencies
./scripts/check-deps

# Verify every CLI/config option actually works against a real kernel (requires
# sudo; not part of CI - see the script's header for why). Run before a release.
./scripts/verify-functionality

# Run tests with code coverage
cd panhandle && cargo tarpaulin --all-features --workspace --out Html --output-dir coverage

# Generate and open documentation
cd panhandle && cargo doc --open

# Or use cargo-docs-rs to view docs.rs style docs locally
cargo docs-rs

# Install git hooks for automatic pre-commit/pre-push checks
./scripts/install-hooks

# Create a release (version bump, changelog, tag, build)
./scripts/release 1.0.26
```

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package panhandle --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

The cross-compiled program
`target/${ARCH}-unknown-linux-musl/release/panhandle` can be copied to a
Linux server or VM and run there.

## Limitations

The minimum kernel version supported is **5.8**, per the
[`RingBuf`](https://docs.rs/aya/latest/aya/maps/ring_buf/struct.RingBuf.html)
map type every build of panhandle loads unconditionally (used for every
event-producing probe: execve, shell, and socket events). Some individual
features need more:

- `--syscalls`/`--comm-allow`/`--comm-deny`/`--block-paths` (system-wide LSM
  blocking): kernel 5.7+ ([`Lsm`](https://docs.rs/aya/latest/aya/programs/lsm/struct.Lsm.html)).
- `--cgroup` (cgroup-scoped LSM blocking): kernel 6.0+
  ([`LsmCgroup`](https://docs.rs/aya/latest/aya/programs/lsm_cgroup/struct.LsmCgroup.html)).
- `--socket`/`--bound` (BTF tracepoints and fentry/fexit programs): kernel
  5.5+, and require `CONFIG_DEBUG_INFO_BTF=y`.
- `--syscalls`/`--cgroup` additionally require `CONFIG_BPF_LSM=y`, and "bpf"
  in the kernel's active LSM list (`/sys/kernel/security/lsm`, usually set
  via the `lsm=` boot parameter) to actually enforce anything - otherwise
  the program attaches without error but blocks nothing. panhandle detects
  this and prints a warning at startup rather than failing silently.
