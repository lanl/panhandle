#!/bin/bash
# Install Rust toolchain and development dependencies for panhandle
set -euo pipefail

echo "=== Installing Rust toolchain ==="
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

echo "=== Installing required Rust toolchains ==="
rustup toolchain install stable
rustup toolchain install nightly --component rust-src

echo "=== Installing bpf-linker ==="
cargo install bpf-linker

echo "=== Installing development tools ==="
cargo install cargo-audit
cargo install cargo-outdated
cargo install cargo-machete
cargo install cargo-deny
cargo install cargo-sbom

echo "=== Installing cross-compilation target (optional) ==="
rustup target add x86_64-unknown-linux-musl

echo "=== Rust installation complete! ==="
echo "Run 'source ~/.cargo/env' or restart your shell"
