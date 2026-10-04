#!/bin/sh
# Client XDP mode: needs the eBPF toolchain (see README). The kernel tests run
# as root in isolated namespaces.
set -eu
cd "$(dirname "$0")/.."
cargo test --locked -p edup-client --features xdp
if [ "$(id -u)" = 0 ]; then
    runner=
else
    # Build as the current user; only the tests run as root.
    target_key=$(rustc -vV | sed -n 's/^host: //p' | tr '[:lower:]-' '[:upper:]_')
    runner="CARGO_TARGET_${target_key}_RUNNER=sudo"
fi
env $runner cargo test --locked -p edup-client --features xdp --bin edup-client -- --ignored xdp::tests
for test in isolated_xdp_client isolated_xdp_ipv6_client isolated_xdp_router; do
    env $runner cargo test --locked -p edup-client --features xdp --test lifecycle -- --ignored --exact "$test" --nocapture
done
