# edup

edup is a lightweight IPv4 and IPv6 tunnel over UDP, written in Rust. It connects Linux
and Windows clients through a Linux server, carrying IPv4/IPv6 TCP, UDP, and ICMP/ICMPv6 echo
traffic from a virtual TUN interface to the Internet.

The server processes tunnel packets and performs NAT entirely in XDP/eBPF.
A small dispatcher selects separate IPv4 and IPv6 programs.
The userspace loader configures and pins them, then exits; no server
process is needed to keep forwarding traffic.

## Key features

- **Linux and Windows clients:** Linux TUN and Windows Wintun support.
- **XDP forwarding:** handled packets bypass the server's host IP stack;
  unrelated traffic, including SSH and ARP, passes through normally.
- **Multiple users:** static user IDs, automatic endpoint learning, and periodic
  KEEPALIVE. A client receives `tunnel_net + user` for IPv4 or
  `tunnel_net6 + user` for IPv6.
- **Automatic routing:** a physical route to the server and two `/1` routes
  through TUN for the selected address family, with cleanup on graceful shutdown.
  Manual routing is also supported.
- **Low overhead:** 36 bytes over IPv4 or 56 bytes over IPv6, TCP MSS clamping, Linux GSO/GRO and
  Windows USO/URO, with fallback when offloads are unavailable.
- **Server management:** configuration validation, atomic reload, user endpoint
  inspection, and packet counters. Reload resets NAT and active connections.

The protocol uses shared-password obfuscation, **not cryptographic encryption or
authentication**. Fragmented packets, IPv6 extension headers, ICMP/ICMPv6 error
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
kernel/driver supporting XDP BPF links and BPF ISA v3; Rust is not needed on the
server. The `deploy/` directory contains systemd units.

## Configuration

Both configurations use TOML and reject unknown fields. Replace the example
addresses and password. The password and tunnel network must match on both
sides, and the client user ID must be enabled on the server.

### Server

Example: `config/server.example.toml`.

```toml
interface = "eth0"              # NIC used for XDP forwarding
server_ip = "192.0.2.1"          # Address receiving tunnel UDP
nat_ip = "192.0.2.1"             # Public source address for NAT
port = 7777
password = "replace-this-password"
tunnel_net = "10.66.0.0/16"
nat_port_min = 20000
nat_port_max = 29999
max_frame = 1500                 # Maximum outer IP packet size
xdp_mode = "driver"              # Native XDP; "skb" for generic XDP
users = [7, 42]
```

The NAT range must exclude the tunnel port, host service ports, and the host's
`net.ipv4.ip_local_port_range`. `max_frame` must not exceed the NIC MTU. The
loader checks these conditions but does not configure the host network.

### Client

Example: `config/client.example.toml`.

```toml
server = "192.0.2.1:7777"        # Or "[2001:db8::1]:7777" for IPv6 UDP
user = 7                        # Tunnel address: 10.66.0.7
password = "replace-this-password"
tunnel_net = "10.66.0.0/16"
interface = "edup0"
mtu = 1464
keepalive_secs = 15
routes = true                   # false: configure routes manually
offload = true                  # false: disable TUN/UDP offloads
# wintun_dll = 'C:\edup\wintun.dll'  # Optional Windows override
```

IPv4 tunnel networks accept prefixes `/1` through `/16` with zero host bits. User
IDs must be nonzero and cannot be the IPv4 network's broadcast address. Use each
ID on one active client at a time. Client MTU must be at most both the path MTU
and server's `max_frame`, minus the outer overhead: 36 for IPv4 or 56 for IPv6.
For outer MTU 1500, use 1464 for IPv4 or **1444 for IPv6**. Reduce it for smaller
paths. KEEPALIVE accepts 1-60 seconds.

### IPv6

IPv6 is a separate tunnel mode: IPv6 packets travel over IPv6 UDP; IPv4 packets
travel over IPv4 UDP. The client's `server` address selects the mode. Only that
family's address and routes are configured on TUN. Existing IPv4 configurations
remain valid, and both server programs can serve their respective clients on
the same NIC and UDP port. Mixed-family payloads are rejected.

Add all three fields to enable the server's IPv6 listener and NAT66 forwarding:

```toml
server_ip6 = "2001:db8::1"
nat_ip6 = "2001:db8::1"
tunnel_net6 = "fd66::/112"
```

Use this IPv6 client configuration:

```toml
server = "[2001:db8::1]:7777"
user = 7
password = "replace-this-password"
tunnel_net6 = "fd66::/112"
interface = "edup6"
mtu = 1444
keepalive_secs = 15
routes = true
offload = true
```

The client receives `fd66::7/128`. `tunnel_net6` must match on both sides and use
a global unicast or ULA /112 network with zero host bits. IPv6 supports TCP, UDP,
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

Upgrade both binaries for IPv6. Reload atomically replaces the dispatcher and
its protocol programs, and clears NAT mappings and learned endpoints.

Validate with `edup-server --config server.toml check` or
`edup-client --config client.toml check`. Start the server with
`edup-server --config server.toml up` and the client with
`edup-client --config client.toml run`, using the required privileges.
Stop the client with Ctrl+C; stop the server with `edup-server down`.