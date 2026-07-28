# panhandle

A user activity monitoring tool for High Performance Computing systems using eBPF. Monitors shell commands, process execution, and system resource usage with minimal performance impact.

## How to set up Development Environment

1. Stable rust toolchains: `rustup toolchain install stable`
2. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)
3. Nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
4. Optional: (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
5. Optional: (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
6. Optional: (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
7. Sudo for your user is required.

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
```

Cargo build scripts are used to automatically build the eBPF bytecode correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package panhandle --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker="${ARCH}-linux-musl-gcc"
```

The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/panhandle` can be
copied to a Linux server or VM and run there.

## Aya eBPF Version Compatibility

**This project currently uses Aya v0.14.0 with the synchronous PerfEventArray API**.

- The synchronous API uses `.for_each()` method for event processing
- This replaces the older async API that used `AsyncPerfEventArrayBuffer`
- All eBPF maps now use the synchronous event consumption pattern

## Limitations

- Minimum kernel version supported: 4.3 (per [PerfEventArray docs](https://docs.rs/aya/latest/aya/maps/perf/struct.PerfEventArray.html))
- Currently uses synchronous API only - async support may be added in future versions
