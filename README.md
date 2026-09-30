# edup

edup is a lightweight IPv4 and IPv6 tunnel over UDP, written in Rust. It connects Linux
and Windows clients through a Linux server, carrying IPv4/IPv6 TCP, UDP, and ICMP/ICMPv6 echo
traffic from a virtual TUN interface to the Internet. Every packet is encrypted and
authenticated with ChaCha20-Poly1305 and protected against replay.

The server processes tunnel packets, including the cryptography, and performs NAT
entirely in XDP/eBPF.
A small dispatcher selects separate IPv4 and IPv6 programs.
The userspace loader configures and pins them, then exits; no server
process is needed to keep forwarding traffic.

## Security

edup is a lightweight tunnel with per-user keys, not a full VPN suite. Protocol v5
([specification](docs/protocol-v5.md)) protects against an attacker who can observe,
drop, delay, reorder, replay, modify and inject tunnel packets:

- **Confidentiality and integrity:** RFC 8439 ChaCha20-Poly1305 for every packet.
  Forged or modified packets are dropped before they change any server state.
- **Replay protection:** 48-bit per-packet counters with sliding windows. Each packet
  is accepted at most once, and stale packets are refused.
- **Fresh session keys:** a one-round-trip handshake derives new keys from each client
  start and each server load, so recorded traffic from earlier sessions is never
  accepted again. Replayed handshakes cannot disturb an established session.
- **Return path:** only authenticated, fresh packets can change a user's learned
  endpoint, so forged, replayed or delayed packets cannot redirect return traffic.
- **User isolation:** one user's key cannot act as another user.

Not provided:

- **No forward secrecy.** A leaked password exposes recorded traffic.
- **No identity hiding.** User IDs, packet sizes and timing are visible.
- **No protection against password guessing.** Passwords are hashed once
  (BLAKE2s), and a captured handshake allows offline guessing. Use generated
  credentials (`edup-client credentials`, 256 bits).
- **No denial-of-service resistance.** An on-path attacker can always drop traffic.
- **No DNS or leak protection.** DNS settings stay unchanged and there is no kill switch.

## Key features

- **Linux and Windows clients:** Linux TUN and Windows Wintun support.
- **XDP forwarding:** handled packets bypass the server's host IP stack;
  unrelated traffic, including SSH and ARP, passes through normally.
- **Authenticated encryption in XDP:** ChaCha20-Poly1305, HChaCha20 session keys and
  replay windows run inside the XDP programs; no server process handles packets.
- **Multiple users:** random signed 64-bit user IDs, individual passwords, automatic
  endpoint learning, and periodic authenticated KEEPALIVE. Clients choose their local TUN
  addresses independently; different users may use identical addresses.
- **Automatic routing:** a physical route to the server and two `/1` routes
  through TUN for the selected address family, with cleanup on graceful shutdown.
  Manual routing is also supported.
- **Low overhead:** 50 bytes over IPv4 or 62 bytes over IPv6 (a compact inner header
  offsets the 32-byte authenticated header), TCP MSS clamping, Linux GSO/GRO and
  Windows USO/URO, with fallback when offloads are unavailable.
- **Server management:** configuration validation, atomic reload, user endpoint
  inspection, and packet counters. Reload resets NAT, active connections and
  sessions; clients handshake again automatically.

Fragmented packets, IPv6 extension headers, ICMP/ICMPv6 error
translation, and client-to-client forwarding are unsupported. DNS settings remain
unchanged; there is no kill switch. IPv6 tunnel routing is opt-in. The server
assumes one Ethernet NIC and upstream gateway, without VLAN encapsulation;
IPv6 neighbor discovery and unrelated host traffic pass to the host stack.

## Build

Run commands from the repository root with Rust and Cargo installed.

### Client — Linux or Windows

```sh
cargo build --locked --release -p edup-client
```

Output: `target/release/edup-client` on Linux or
`target/release/edup-client.exe` on Windows.

Linux runtime requires root, `/dev/net/tun`, and `iproute2`. Windows requires
Administrator privileges and an architecture-matching `wintun.dll` beside the
executable, or an absolute DLL path in the configuration.

### Server — Linux or WSL

Install the pinned eBPF toolchain and linker, then build:

```sh
rustup toolchain install nightly-2026-09-26 --profile minimal --component rust-src
cargo install bpf-linker --version 0.11.1 --locked
cargo build --locked --release -p edup-server
```

Output: `target/release/edup-server`. The eBPF program is built automatically and
embedded in this executable. Deployment requires root, mounted bpffs, and a
kernel/driver supporting XDP BPF links, BPF atomics (compare-and-exchange), BTF
global functions, and tail calls from programs with BPF-to-BPF calls (Linux 5.12
or newer). Rust is not needed on the server. The `deploy/` directory contains
systemd units. The programs are tested on Linux 6.18; older kernels verify less
precisely, so check with `edup-server up` on a test machine first.

## Configuration

Both configurations use TOML and reject unknown fields. Replace the example
addresses and password. The client user ID and password must match a server
user entry. TUN addresses are local client settings; no address negotiation or
shared tunnel network is needed.

### Server

Example: `config/server.example.toml`.

```toml
interface = "eth0"              # NIC used for XDP forwarding
server_ip = "192.0.2.1"          # Address receiving tunnel UDP
nat_ip = "192.0.2.1"             # Public source address for NAT
port = 7777
nat_port_min = 20000
nat_port_max = 29999
max_frame = 1500                 # Maximum outer IP packet size
xdp_mode = "driver"              # Native XDP; "skb" for generic XDP

[[users]]
id = 4829017365182049271
password = "replace-this-password"

[[users]]
id = -738215604982170351
password = "replace-second-password"
```

The NAT range must exclude the tunnel port, host service ports, and the host's
`net.ipv4.ip_local_port_range`. `max_frame` must not exceed the NIC MTU. The
loader checks these conditions but does not configure the host network.

### Client

Example: `config/client.example.toml`.

```toml
server = "192.0.2.1:7777"        # Or "[2001:db8::1]:7777" for IPv6 UDP
user = 4829017365182049271       # Public routing ID
password = "replace-this-password"
tunnel_ip = "10.66.0.7"          # Optional; default 10.66.0.1
interface = "edup0"
mtu = 1450
keepalive_secs = 15
routes = true                   # false: configure routes manually
offload = true                  # false: disable TUN/UDP offloads
# wintun_dll = 'C:\edup\wintun.dll'  # Optional Windows override
```

User IDs accept the full signed int64 range. The server supports up to 65535
unique users and assigns internal indexes from config order: first user = 1,
second = 2, etc. These indexes never appear in client configuration or on the
wire. Reordering users changes only server indexes; reload clears existing NAT
connections, and clients continue with their unchanged credentials and addresses.
Use each user on one active client at a time.

`tunnel_ip` defaults to `10.66.0.1` and is configured as a /32 on the client.
`tunnel_ip6` defaults to `fd66::1` and is configured as a /128 in IPv6 mode.
Choose a valid unicast address suitable for your local routing; it must differ
from the server address. Other clients can use exactly the same address.
The server keys NAT by user, port/echo ID, protocol, and IP family. The client's
local address is omitted in both directions for IPv4 and IPv6; each user
represents one client address in its selected family. Different users can use identical local addresses and ports.
Client MTU must be at most both the path MTU and server's `max_frame`, minus
the tunnel overhead: 50 for IPv4 or 62 for IPv6. For outer MTU 1500, use 1450
for IPv4 or **1438 for IPv6**. Reduce it for smaller paths. KEEPALIVE accepts
1-60 seconds. A KEEPALIVE left unanswered for 5 seconds (for example after a
server reload) makes the client handshake again; data sent before the new
session is established is dropped.

### IPv6

IPv6 is a separate tunnel mode: IPv6 packets travel over IPv6 UDP; IPv4 packets
travel over IPv4 UDP. The client's `server` address selects the mode. Only that
family's address and routes are configured on TUN. Both server programs can
serve their respective clients on the same NIC and UDP port. Mixed-family payloads are rejected.

Add both fields at the top level, **before any `[[users]]` tables**, to
enable the server's IPv6 listener and NAT66 forwarding:

```toml
server_ip6 = "2001:db8::1"
nat_ip6 = "2001:db8::1"
```

Use this IPv6 client configuration:

```toml
server = "[2001:db8::1]:7777"
user = 4829017365182049271
password = "replace-this-password"
tunnel_ip6 = "fd66::7"           # Optional; default fd66::1
interface = "edup6"
mtu = 1438
keepalive_secs = 15
routes = true
offload = true
```

The example client uses local address `fd66::7/128`. It need not match any
server-side network. IPv6 supports TCP, UDP,
and ICMPv6 echo via NAT66. Its TUN MTU must be at least 1280. Automatic routing
adds `::/1` and `8000::/1` via TUN, plus a physical `/128` route to the server,
and removes owned routes on shutdown. IPv4 routes remain unchanged in this mode.
Use global/ULA server addresses; scoped link-local and IPv4-mapped IPv6 literals
are rejected.

Assign the server's IPv6 addresses to its NIC beforehand so the host handles
neighbor discovery. The loader does not configure host addresses or routes.
By default, Internet packets go to the Ethernet peer learned from incoming
tunnel packets, assuming clients arrive through the upstream gateway. For
clients on the server's local Ethernet segment, set `gateway_mac` (IPv4) or
`gateway6_mac` (IPv6) to the upstream MAC, e.g. `"02:01:02:03:04:05"`. These
optional overrides are static; reload after a gateway MAC change.

Upgrade both binaries together for protocol v5; v4 clients cannot connect. Reload
atomically replaces the dispatcher and its protocol programs, and clears NAT
mappings, learned endpoints and sessions. The packet layouts, handshake and XDP
program structure are documented in [protocol v5](docs/protocol-v5.md).

### Performance

The cryptography dominates the per-packet cost. These medians are from an
AMD Ryzen 7 7800X3D; `BPF_PROG_TEST_RUN` numbers include about 0.3 µs of
syscall overhead.

| | 40-byte packet | 1400-byte packet |
|-|---------------:|-----------------:|
| Server XDP, v4 obfuscation | 0.4-0.5 µs | 1.1 µs |
| Server XDP, v5 encryption, either direction | 0.9-1.0 µs | 5.8 µs |
| Client seal or open (portable x86-64 build) | 0.2 µs | 1.4 µs |

One core's XDP path handles about 2 Gbit/s of full-size packets per direction.
RSS spreads flows over cores. Reproduce with `xdp_check <object> --bench` (root)
and `cargo run --release -p edup-common --features std --example wire_bench`.

Validate with `edup-server --config server.toml check` or
`edup-client --config client.toml check`. Start the server with
`edup-server --config server.toml up` and the client with
`edup-client --config client.toml run`, using the required privileges.
Stop the client with Ctrl+C; stop the server with `edup-server down`.
