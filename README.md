# edup

edup is a lightweight IPv4 tunnel over UDP, written in Rust. It connects Linux
and Windows clients through a Linux server, carrying TCP, UDP, and ICMP echo
traffic from a virtual TUN interface to the Internet.

The server processes tunnel packets and performs NAT entirely in XDP/eBPF.
Its userspace loader configures and pins the program, then exits; no server
process is needed to keep forwarding traffic.

## Key features

- **Linux and Windows clients:** Linux TUN and Windows Wintun support.
- **XDP forwarding:** handled packets bypass the server's host IP stack;
  unrelated traffic, including SSH and ARP, passes through normally.
- **Multiple users:** static user IDs, automatic endpoint learning, and periodic
  KEEPALIVE. Each user receives the address `tunnel_net + user`.
- **Automatic IPv4 routing:** a physical route to the server and two `/1` routes
  through TUN, with cleanup on graceful shutdown. Manual routing is also supported.
- **Low overhead:** 36 bytes per packet, TCP MSS clamping, Linux GSO/GRO and
  Windows USO/URO, with fallback when offloads are unavailable.
- **Server management:** configuration validation, atomic reload, user endpoint
  inspection, and packet counters. Reload resets NAT and active connections.

The protocol uses shared-password obfuscation, **not cryptographic encryption or
authentication**. IPv6, fragmented packets, ICMP error translation, and
client-to-client forwarding are unsupported. DNS settings and IPv6 routes remain
unchanged; there is no kill switch. The server assumes one Ethernet NIC and one
upstream gateway, without VLAN encapsulation.

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
max_frame = 1500                 # Maximum outer IPv4 packet size
xdp_mode = "driver"              # Native XDP; "skb" for generic XDP
users = [7, 42]
```

The NAT range must exclude the tunnel port, host service ports, and the host's
`net.ipv4.ip_local_port_range`. `max_frame` must not exceed the NIC MTU. The
loader checks these conditions but does not configure the host network.

### Client

Example: `config/client.example.toml`.

```toml
server = "192.0.2.1:7777"        # Literal IPv4 address and UDP port
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

Tunnel networks accept prefixes `/1` through `/16` with zero host bits. User
IDs must be nonzero and cannot be the network's broadcast address. Use each ID
on one active client at a time. Client MTU must be at most the path MTU minus 36
and the server's `max_frame` minus 36; 1464 fits an outer MTU of 1500. Reduce it
for smaller paths. KEEPALIVE accepts 1–60 seconds.

Validate with `edup-server --config server.toml check` or
`edup-client --config client.toml check`. Start the server with
`edup-server --config server.toml up` and the client with
`edup-client --config client.toml run`, using the required privileges.
Stop the client with Ctrl+C; stop the server with `edup-server down`.