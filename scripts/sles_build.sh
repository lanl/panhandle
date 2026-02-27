#!/bin/bash
# script to build on rz-m001
#export OPENSSL_INCLUDE_DIR="/usr/include/openssl"
#export OPENSSL_LIB_DIR="/etc/ssl"
cd /root/skip/panhandle/panhandle
rm -f /root/skip/panhandle/rpmbuild/sles/panhandle*.rpm
#cargo install cross
git pull
rustup update
cargo update
## x86 build
rustup target add x86_64-unknown-linux-gnu
cargo build --target=x86_64-unknown-linux-gnu --bin panhandle --release --all-features 
strip -s target/release/panhandle
cargo generate-rpm --arch x86_64 --package panhandle --output /root/skip/panhandle/rpmbuild/sles/
rename -o '.x86_64.rpm' '.sle15.x86_64.rpm' /root/skip/panhandle/rpmbuild/sles/panhandle*.rpm
# clean
cargo clean
## aarch64 build
#rustup target add aarch64-unknown-linux-gnu
#cargo build --target=aarch64-unknown-linux-gnu --bin panhandle --release --all-features 
#strip -s target/release/panhandle
#cargo generate-rpm --arch aarch64 --package panhandle --output /root/skip/panhandle/rpmbuild/sles/
#rename -o '.aarch64.rpm' '.sle15.aarch64.rpm' /root/skip/panhandle/rpmbuild/sles/panhandle*.rpm