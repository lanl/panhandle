# panhandle

## How to set up Development Environment

1. stable rust toolchains: `rustup toolchain install stable`
2. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)
3. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
4. Optional: (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
5. Optional: (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
6. Optional: (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
7. Sudo for your user is required.

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release'
```

Cargo build scripts are used to automatically build the eBPF bytecode correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package panhandle --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/panhandle` can be
copied to a Linux server or VM and run there.

## limitations

The minimum kernel version supported is 4.3 per the [PerfEventArray / AsyncPerfEventArray docs](https://docs.rs/aya/latest/aya/maps/perf/struct.AsyncPerfEventArray.html)
