#!/bin/sh
# OpenWrt client: a static aarch64 musl executable with XDP mode, built with
# cargo-zigbuild and the eBPF toolchain (see README). With SDK=<OpenWrt SDK
# directory>, also builds the edup-client and luci-app-edup apk packages.
#
#   scripts/build-openwrt.sh
#   SDK=~/openwrt/openwrt-sdk-25.12.2-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64 scripts/build-openwrt.sh
#
# Output: dist/openwrt/.
set -eu
cd "$(dirname "$0")/.."
repo=$(pwd)
target=${TARGET:-aarch64-unknown-linux-musl}
target_dir=${CARGO_TARGET_DIR:-$repo/target}
out=$repo/dist/openwrt
mkdir -p "$out"

cargo +stable zigbuild --locked --release --target "$target" -p edup-client --features xdp
binary=$out/edup-client
cp "$target_dir/$target/release/edup-client" "$binary"
# Strip only the executable: a profile setting would reach the nested eBPF
# build too, whose object needs its BTF and symbols.
if command -v llvm-strip >/dev/null; then
    llvm-strip "$binary"
fi
echo "built $binary"

[ -n "${SDK:-}" ] || exit 0
cd "$SDK"
if ! grep -q '^src-link edup ' feeds.conf 2>/dev/null; then
    grep -v '^src-link edup ' feeds.conf.default > feeds.conf
    echo "src-link edup $repo/openwrt" >> feeds.conf
fi
./scripts/feeds update edup >/dev/null
./scripts/feeds install -p edup edup-client luci-app-edup >/dev/null
make defconfig >/dev/null
make package/edup-client/compile package/luci-app-edup/compile \
    EDUP_BINARY="$binary" -j"$(nproc)" ${V:+V=$V}
find bin/packages -name 'edup-client*.apk' -exec cp {} "$out/" \;
find bin/packages -name 'luci-app-edup*.apk' -exec cp {} "$out/" \;
ls -l "$out"
