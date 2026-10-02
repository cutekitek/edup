# edup

edup is a lightweight IPv4 and IPv6 tunnel over UDP, written in Rust. It connects Linux
and Windows clients through a Linux server, carrying IPv4/IPv6 TCP, UDP, and ICMP/ICMPv6 echo
traffic from a virtual TUN interface to the Internet.

The server processes tunnel packets and performs NAT entirely in XDP/eBPF so it works insanely fast.
A small dispatcher selects separate IPv4 and IPv6 programs.
The userspace loader configures and pins them, then exits; no server
process is needed to keep forwarding traffic.

## SECURITY DISCLAIMER

edup is an **obfuscated proxy implemented as an IP-over-UDP tunnel**, intended for
use on **trusted networks with trusted participants**. It provides lightweight
traffic forwarding and NAT, with per-user password obfuscation of tunnel packets.

It is **not a secure VPN or an encrypted transport protocol**. Obfuscation does
not provide cryptographic confidentiality, integrity, peer authentication, or
replay protection. The passwords and user IDs do not provide secure
isolation between users. An attacker able to observe or inject tunnel traffic
may recover packet contents, forge or replay packets, redirect return traffic,
or disrupt connections.

Do not rely on edup to protect sensitive traffic on untrusted networks, provide
anonymity, or enforce a security boundary. Use application-level encryption
such as TLS for sensitive data, and a separate authenticated, encrypted tunnel
when the network path is untrusted.

## Key features

- **Linux and Windows clients:** Linux TUN and Windows Wintun support.
- **XDP forwarding:** handled packets bypass the server's host IP stack;
  unrelated traffic, including SSH and ARP, passes through normally.
- **Linux XDP client mode:** optionally, eBPF on the client's network interface
  carries the tunnel and routes each destination from a cache that userspace
  fills on demand, without system routes; see [XDP mode](#xdp-mode-linux).
- **Multiple users:** random signed 64-bit user IDs, individual passwords, automatic
  endpoint learning, and periodic KEEPALIVE. Clients choose their local TUN
  addresses independently; different users may use identical addresses.
- **Client routing rules:** proxy or bypass by CIDR, domain or sing-box `.srs`
  rule-sets (GeoIP and geosite), first match wins, with a default for everything else.
  Routes are installed for the selected address family and removed on graceful
  shutdown. Manual routing is also supported.
- **Low overhead:** 27 bytes over IPv4 or 39 bytes over IPv6, TCP MSS clamping, Linux GSO/GRO and
  Windows USO/URO, with fallback when offloads are unavailable.
- **Server management:** configuration validation, atomic reload, user endpoint
  inspection, and packet counters. Reload resets NAT and active connections.

Fragmented packets, IPv6 extension headers, ICMP/ICMPv6 error
translation, and client-to-client forwarding are unsupported. DNS settings remain
unchanged unless domain rules are configured; there is no kill switch. IPv6 tunnel routing is opt-in. The server
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

The Linux [XDP mode](#xdp-mode-linux) needs the `xdp` feature, built with the
server's eBPF toolchain (see below):

```sh
cargo build --locked --release -p edup-client --features xdp
```

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

Both configurations are JSON files and reject unknown fields. `//` and `/* */`
comments are allowed. Replace the example addresses and password. The client
user ID and password must match a server user entry. TUN addresses are local
client settings; no address negotiation or shared tunnel network is needed.

### Server

Example: `config/server.example.json`.

```jsonc
{
  "interface": "eth0",          // NIC used for XDP forwarding
  "server_ip": "192.0.2.1",     // Address receiving tunnel UDP
  "nat_ip": "192.0.2.1",        // Public source address for NAT
  "port": 7777,
  "nat_port_min": 20000,
  "nat_port_max": 29999,
  "max_frame": 1500,            // Maximum outer IP packet size
  "xdp_mode": "driver",         // Native XDP; "skb" for generic XDP
  "users": [
    { "id": 4829017365182049271, "password": "replace-this-password" },
    { "id": -738215604982170351, "password": "replace-second-password" }
  ]
}
```

The NAT range must exclude the tunnel port, host service ports, and the host's
`net.ipv4.ip_local_port_range`. `max_frame` must not exceed the NIC MTU. The
loader checks these conditions but does not configure the host network.

### Client

Example: `config/client.example.json`.

```jsonc
{
  // "mode": "xdp",                 // Linux eBPF datapath; default "tun"
  "server": "192.0.2.1:7777",       // Or "[2001:db8::1]:7777" for IPv6 UDP
  "user": 4829017365182049271,      // Public routing ID
  "password": "replace-this-password",
  "tunnel_ip": "10.66.0.7",         // Optional; default 10.66.0.1
  "interface": "edup0",
  "mtu": 1473,
  "keepalive_secs": 15,
  "offload": true,                  // false: disable TUN/UDP offloads
  // "wintun_dll": "C:\\edup\\wintun.dll",  // Optional Windows override
  "routing": {
    "default_route": "proxy",
    "routes": [
      { "ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], "to": "bypass" },
      { "rules": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs", "to": "bypass" }
    ]
  }
}
```

`edup-client credentials` prints a new random `user` and `password` pair.

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
the tunnel overhead: 27 for IPv4 or 39 for IPv6. For outer MTU 1500, use 1473
for IPv4 or **1461 for IPv6**. Reduce it for smaller paths. KEEPALIVE accepts
1-60 seconds.

### Client routing

`routing.default_route` is `"proxy"` (through the tunnel, the default) or
`"bypass"` (the physical network). Each entry of `routing.routes` sends matching
destinations `"to": "proxy"` or `"to": "bypass"`:

- `"ip"`: a CIDR prefix or single address.
- `"domain"`: an exact name, e.g. `"example.ru"`.
- `"domain_suffix"`: `".ru"` or `".example.ru"` matches every subdomain, by
  comparing the end of the name; add the name itself with `"domain"`. Without
  the leading dot, as in sing-box, `"example.ru"` also matches itself.
- `"domain_keyword"`: a substring of the name.
- `"rules"`: a sing-box binary rule-set (`.srs`, versions 1-5): an
  `http://`/`https://` URL or a file path relative to the configuration.

Each field takes one value or an array, and an entry may combine fields; it
matches when any of them does. Rules are ordered: the first entry matching a
destination address or its name decides the route, so put exceptions before
broader rules. Only the tunnel's address family is routed; IPv6 entries and
answers are ignored in IPv4 mode and vice versa. Use punycode for
internationalized names.

From a rule-set, `ip_cidr`, `domain`, `domain_suffix` and `domain_keyword`
items are used, which covers GeoIP and geosite rule-sets. Rules with
`domain_regex`, AdGuard filters, inverted or AND-combined name rules, or a port,
network, process or other condition are skipped; the client reports how many. Rule-sets are downloaded at every start, before routes change.
Each successful download is cached in `rule-sets/` beside the configuration
and used when a later download fails.

#### Domain rules and DNS

Routes see addresses, not names. When any rule contains names, the client runs
a DNS forwarder on its tunnel address, port 53 (UDP and TCP), and points the
system resolver at it through the TUN interface: systemd-resolved on Linux
(`resolvectl`, routing domain `~.`), and the adapter's DNS server and interface
metric on Windows. These settings disappear with the interface, even if the
client crashes. Queries go to `dns.servers` (default `1.1.1.1` and `8.8.8.8`,
or Cloudflare and Google IPv6 resolvers in IPv6 mode), which are routed like
any other destination. Before an answer reaches the application, each of its
addresses for a matched name gets a host route through the tunnel or the
default route, unless the static routes already send it that way, so the first
connection already follows the rule. Host routes stay until the client stops.

```jsonc
"routing": {
  "default_route": "proxy",
  "routes": [
    { "domain": "example.ru", "domain_suffix": ".ru", "to": "bypass" },
    { "rules": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ru.srs", "to": "bypass" }
  ]
},
"dns": { "servers": ["1.1.1.1", "8.8.8.8"], "set_system": true }
```

Name-based routing is only as complete as the DNS traffic the forwarder sees:
- Applications resolving names themselves, such as browsers using DNS over
  HTTPS, bypass it; disable their secure DNS for domain rules to apply.
- Addresses cached before the client started keep their old route until the
  name is resolved again; the client flushes the system cache at start.
- One address shared by names with different rules, as on CDNs, follows the
  most recent answer.
- On Linux, `/etc/resolv.conf` must use the systemd-resolved stub
  (`127.0.0.53`); the client warns otherwise.
- On Windows, other adapters' resolvers may still be asked in parallel.

With `"set_system": false` the forwarder runs without changing system DNS;
send queries to `<tunnel address>:53` yourself.

The client turns the rules into the fewest routes: proxied prefixes via TUN,
or a `/1` via TUN with bypassed prefixes via the system's preferred default
route, plus a physical host route to the server when a tunnel route covers it.
Large rule-sets produce thousands of routes; they are added through netlink on
Linux and the IP Helper API on Windows, and removed on shutdown. Existing more
specific system routes, such as the local network, keep precedence.
`"default_route": "bypass"` with no `routes` changes no routes at all: route
traffic into the TUN manually. `edup-client check` prints the resulting route
counts.

### XDP mode (Linux)

`"mode": "xdp"` (default `"tun"`) needs a client built with `--features xdp`.
Instead of routes into the TUN device, eBPF programs on the network interface
of the route to the server carry the tunnel and route each destination:

- A TC egress program looks up every outgoing packet's destination in a route
  cache (up to 131072 addresses, least recently used first out). Packets to
  bypassed destinations continue unchanged; packets to proxied destinations are
  encapsulated in the kernel and sent to the server.
- An unknown destination is a route lookup: the program marks it pending and
  hands the packet to the client through the TUN device. The client decides the
  route with the same rules as TUN mode, stores it in the cache and sends the
  packet again, which now follows the stored route. Later packets to that
  destination stay in the kernel.
- An XDP program on the same interface decapsulates the server's packets and
  passes them to the local stack as ordinary packets for the interface address.
- Packets follow the standard route, the one the system uses without edup,
  whenever the client fails to respond: while its heartbeat is older than 2
  seconds (the client is stopped, hung or killed), and when a lookup stays
  unanswered for 0.5 seconds, until the destination is looked up again 5
  seconds after the request. Packets never wait for the client.

Routing rules apply as in TUN mode: the first matching rule decides, otherwise
`default_route`. The server and multicast or broadcast addresses always take the
standard route, as do destinations of the interface's other system routes, such
as the local network. Domain rules update the cache from DNS answers, including
destinations already cached. `"default_route": "bypass"` without `routes` is
rejected in this mode.

```jsonc
{
  "mode": "xdp",
  "xdp_mode": "auto",   // native XDP if the driver supports it; "driver" or "skb"
  "server": "192.0.2.1:7777",
  // ...the TUN mode settings; interface names have at most 14 characters
}
```

Requirements and limitations:
- Linux 5.10 or newer, root, and an Ethernet or Wi-Fi interface. Linux 6.6
  and newer attach the TC programs as links (TCX) that disappear with the
  client. Older kernels use a `clsact` qdisc; programs left there by a crash
  only pass traffic to the standard route and are replaced at the next start.
- The TUN device `interface` still exists, without routes: it carries lookups
  and the DNS forwarder's address. A veth pair `<interface>s`/`<interface>e`
  carries proxied packets, so that the kernel completes TSO/GSO segmentation
  and checksums before encapsulation. A pair left by a crash is removed at the
  next start. Native XDP may briefly reset some drivers' interfaces.
- Only traffic through that interface from the address of its route to the
  server is routed; the client prints both at start. Replies carry no local
  address, so traffic from other addresses, such as IPv6 temporary addresses,
  keeps the standard route. Restart the client after the interface's
  addresses or networks change.
- `mtu` must fit the interface MTU minus the tunnel overhead. TCP MSS is
  clamped in both directions; larger UDP and other packets to proxied
  destinations are dropped, not fragmented.
- As in TUN mode, existing connections to proxied destinations move into the
  tunnel when the client starts.
- Generic XDP (`"skb"`) runs after GRO: keep `rx-gro-list` disabled on the
  interface (the default), or tunnel packets may arrive coalesced.

At shutdown, and every 5 seconds with `EDUP_DIAGNOSTICS` set, the client prints
lookup and `xdp_*` packet counters.

### IPv6

IPv6 is a separate tunnel mode: IPv6 packets travel over IPv6 UDP; IPv4 packets
travel over IPv4 UDP. The client's `server` address selects the mode. Only that
family's address and routes are configured on TUN. Both server programs can
serve their respective clients on the same NIC and UDP port. Mixed-family payloads are rejected.

Add both fields to the server configuration to enable its IPv6 listener and
NAT66 forwarding:

```jsonc
  "server_ip6": "2001:db8::1",
  "nat_ip6": "2001:db8::1",
```

Use this IPv6 client configuration:

```jsonc
{
  "server": "[2001:db8::1]:7777",
  "user": 4829017365182049271,
  "password": "replace-this-password",
  "tunnel_ip6": "fd66::7",          // Optional; default fd66::1
  "interface": "edup6",
  "mtu": 1461,
  "keepalive_secs": 15,
  "offload": true
}
```

The example client uses local address `fd66::7/128`. It need not match any
server-side network. IPv6 supports TCP, UDP,
and ICMPv6 echo via NAT66. Its TUN MTU must be at least 1280. With the default
routing, the client adds `::/1` and `8000::/1` via TUN, plus a physical `/128`
route to the server, and removes owned routes on shutdown. IPv4 routes remain
unchanged in this mode.
Use global/ULA server addresses; scoped link-local and IPv4-mapped IPv6 literals
are rejected.

Assign the server's IPv6 addresses to its NIC beforehand so the host handles
neighbor discovery. The loader does not configure host addresses or routes.
By default, Internet packets go to the Ethernet peer learned from incoming
tunnel packets, assuming clients arrive through the upstream gateway. For
clients on the server's local Ethernet segment, set `gateway_mac` (IPv4) or
`gateway6_mac` (IPv6) to the upstream MAC, e.g. `"02:01:02:03:04:05"`. These
optional overrides are static; reload after a gateway MAC change.

Upgrade both binaries together for protocol v4. Reload atomically replaces the dispatcher and
its protocol programs, and clears NAT mappings and learned endpoints.
The compact packet layouts are documented in [protocol v4](docs/protocol-v4.md).

Validate with `edup-server --config server.json check` or
`edup-client --config client.json check`. Start the server with
`edup-server --config server.json up` and the client with
`edup-client --config client.json run`, using the required privileges.
Stop the client with Ctrl+C; stop the server with `edup-server down`.
