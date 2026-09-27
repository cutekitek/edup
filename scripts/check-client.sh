#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
cargo test --locked -p edup-client
if [ "$(id -u)" = 0 ]; then
    cargo test --locked -p edup-client --test lifecycle -- --ignored --exact isolated_client --nocapture
else
    # Build as the current user; only the namespace test runs as root.
    target_key=$(rustc -vV | sed -n 's/^host: //p' | tr '[:lower:]-' '[:upper:]_')
    env "CARGO_TARGET_${target_key}_RUNNER=sudo" cargo test --locked -p edup-client --test lifecycle -- --ignored --exact isolated_client --nocapture
fi
