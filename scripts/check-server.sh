#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
cargo test --locked -p edup-server
cargo build --locked -p edup-server
if [ "$(id -u)" = 0 ]; then
    cargo test --locked -p edup-server --test lifecycle -- --ignored --nocapture
else
    # Cargo builds as the current user; only the integration test runs as root.
    target_key=$(rustc -vV | sed -n 's/^host: //p' | tr '[:lower:]-' '[:upper:]_')
    env "CARGO_TARGET_${target_key}_RUNNER=sudo" cargo test --locked -p edup-server --test lifecycle -- --ignored --nocapture
fi
