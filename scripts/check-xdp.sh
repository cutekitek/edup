#!/bin/sh
# Run from Linux/WSL; only the last command needs root. No network changes.
set -eu
cd "$(dirname "$0")/.."
cargo test -p edup-common --features std
cargo +nightly-2026-09-26 build --locked -p edup-ebpf --target bpfel-unknown-none -Z build-std=core --release
cargo build --locked -p edup-common --features aya --example xdp_check
if [ "$(id -u)" = 0 ]; then
    target/debug/examples/xdp_check
else
    sudo target/debug/examples/xdp_check
fi
