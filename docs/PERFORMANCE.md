# Performance work — 2026-09-27

This pass reduces CPU work while retaining the existing wire format, MTU and
configuration. Existing clients remain compatible with the updated server.

## Changes and measurements

The userspace XOR routine now handles complete eight-byte words with safe,
unaligned-compatible loads and stores, followed by a separate short tail.
Previously, each word used a variable-length byte loop. A regression compares
the new output with the original algorithm for every length from 0 through 1536
and all eight offsets, including checks that surrounding bytes stay unchanged.

Windows release CPU benchmark, median of seven runs of one million calls:

| XOR region | Before | After | Reduction in CPU time |
|---|---:|---:|---:|
| 44 bytes (TCP ACK plus protocol header) | 16.47 ns | 6.69 ns | 59% |
| 1404 bytes (1400-byte inner packet plus header) | 433.23 ns | 178.34 ns | 59% |

This is about **2.4× faster XOR**, not a 2.4× improvement in tunnel throughput.
The four-byte KEEPALIVE case is effectively unchanged (about 3–4 ns).

The server's NAT `touch` function now skips a second `NAT_IN` lookup and redundant
state write when the timestamp is less than one second old and the TCP state is
unchanged. Both map ownership checks still run; timestamp refresh, expiry and
TCP state transitions retain their existing rules.

On `eds.cutekitek.dev` (one vCPU, kernel 6.8.0-88), alternating baseline/optimized
kernel test runs measured:

| Established TCP packet | Baseline | Optimized |
|---|---:|---:|
| 40-byte outbound ACK | 608–611 ns | 562–584 ns |
| 40-byte inbound ACK | 610–614 ns | 563–587 ns |
| 1400-byte outbound packet | 2262–2355 ns | 2265–2314 ns |
| 1400-byte inbound packet | 2138–2237 ns | 2087–2204 ns |

Short-packet CPU time improved about **4–8%**. Large-packet results overlap;
there is no demonstrated large-packet speedup. These are kernel test-run timings,
not NIC packet-rate or bandwidth limits. Each sample is a separate test syscall
with fresh input, because XDP mutates packets in place. The benchmark checks that
every packet returns `XDP_TX`, uses a warm-up round, and reports the median of
seven averages of 2000 executions. No test program attaches to an interface.

## Live validation and deployment

The updated server is deployed on `eds.cutekitek.dev`; the previous loader is
saved at `/root/edup-optimize-20260927/edup-server-before`. The packet regression
suite passed on the deployed kernel. SSH and sing-box remained active.

The updated Windows executable and matching profile are in
`local/windows-client-eds-optimized/`; `local/edup-windows-eds.zip` contains this
version. The running client in `local/windows-client-eds/` was left running.
Stop it with Ctrl+C before launching the optimized client with the same user ID.

The optimized Windows client and server passed a real Wintun test: UDP DNS,
1372-byte ping payloads with no fragmentation, HTTPS with exit IP `45.151.73.43`,
10 MB downloaded in 0.73 s (~110 Mbit/s), and Speedtest's server list in 0.29 s.
This does **not** show an internet bandwidth improvement over the previous short
tests (116–125 Mbit/s); network variability exceeds the measured difference.
Tests used temporary user 9 and specific `/32` routes, then disabled the user
and removed the test routes and adapter. The normal profile remains user 8.

Other checks: common/client unit tests, Linux TUN lifecycle, Windows/common/eBPF
Clippy, and byte-for-byte wire compatibility. The existing multi-CPU NAT race
limitations are unchanged.

## Reproduce

```sh
cargo run --locked --release -p edup-common --example wire_bench
cargo build --locked -p edup-common --features aya --example xdp_check
sudo target/debug/examples/xdp_check path/to/edup-ebpf
sudo target/debug/examples/xdp_check path/to/edup-ebpf --bench
```

Run both baseline and candidate binaries on the same machine, alternating their
order and keeping other load stable. Preserve the original BPF object before
rebuilding. The wire benchmark works on Windows and Linux; XDP checks need Linux.

## Next work

Before changing the protocol, measure sustained upload/download and CPU usage
against a controlled peer. The remaining candidates are UDP syscall batching,
Wintun copy costs, and Linux GSO/GRO. They need dedicated loss, latency, shutdown
and compatibility tests. Aggregating several inner packets changes the wire
format and can delay ACKs, so it is not part of this pass. PMTU discovery needs
ICMP-error translation before the client can safely raise MTU automatically.
