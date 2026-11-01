#!/bin/bash
# can run a vanilla sles container something like this:
# podman run  -v /root/panhandle/:/root/ -it  --entrypoint /bin/bash -d registry.suse.com/suse/sle15:15.5 
zypper install -y gcc gcc7 vim
zypper update -y
curl https://sh.rustup.rs -sSf | sh -s -- -y
source ~/.cargo/env
cd ~/panhandle
~/.cargo/bin/rustup toolchain install stable
~/.cargo/bin/rustup toolchain install nightly --component rust-src
~/.cargo/bin/cargo install cargo-generate-rpm bpf-linker
~/.cargo/bin/cargo update
~/.cargo/bin/cargo build --release
strip -s target/release/panhandle
~/.cargo/bin/cargo generate-rpm --package panhandle --output rpmbuild/sles/