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
- **Multiple servers:** a client keeps a tunnel to each configured server at
  once; routing rules name the server by its tag.
- **Router mode:** on a Linux or OpenWrt router in XDP mode, a permanent eBPF
  client table sends each LAN device's traffic through one server, direct, or
  by the routing rules; a LuCI app manages servers, devices and rules. See
  [Router (OpenWrt)](#router-openwrt).
- **Client routing rules:** a server or direct by CIDR, domain or sing-box `.srs`
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
  "servers": [
    {
      "tag": "nl",                  // The name routing rules use
      "server": "192.0.2.1:7777",   // Or "[2001:db8::1]:7777" for IPv6 UDP
      "user": 4829017365182049271,  // Public routing ID
      "password": "replace-this-password"
    },
    { "tag": "de", "server": "198.51.100.1:7777", "user": -738215604982170351, "password": "replace-second-password" }
  ],
  "tunnel_ip": "10.66.0.7",         // Optional; default 10.66.0.1
  "interface": "edup0",
  "mtu": 1473,
  "keepalive_secs": 15,
  "offload": true,                  // false: disable TUN/UDP offloads
  // "wintun_dll": "C:\\edup\\wintun.dll",  // Optional Windows override
  "routing": {
    "default_route": "nl",
    "routes": [
      { "ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], "to": "direct" },
      { "domain_suffix": ".de", "to": "de" },
      { "rules": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs", "to": "direct" }
    ]
  }
}
```

`edup-client credentials` prints a new random `user` and `password` pair.

`servers` lists one or more tunnel servers, all IPv4 or all IPv6 (at most
32). Each has its own tunnel: in TUN mode its own device and address, the
second counting up from the first (`edup1` with `10.66.0.8` here, and so
on), in XDP mode a share of the same eBPF datapath. A tag is up to 32 letters, digits, `_`, `-` or `.`, and not
`direct`, `bypass` or `rules`. The single-server form of earlier versions,
top-level `server`, `user` and `password`, still works: that server has the
tag `proxy`, and `bypass` means `direct`.

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

`routing.default_route` is a server's tag (through its tunnel; the first
server by default) or `"direct"` (the physical network). Each entry of
`routing.routes` sends matching destinations `"to"` a server's tag or
`"direct"`:

- `"ip"`: a CIDR prefix or single address.
- `"domain"`: an exact name, e.g. `"example.ru"`.
- `"domain_suffix"`: `".ru"` or `".example.ru"` matches every subdomain, by
  comparing the end of the name; add the name itself with `"domain"`. Without
  the leading dot, as in sing-box, `"example.ru"` also matches itself.
- `"domain_keyword"`: a substring of the name.
- `"rules"`: a sing-box binary rule-set (`.srs`, versions 1-5): an
  `http://`/`https://` URL or a file path, absolute or relative to the
  configuration, e.g. `"rules": "/etc/edup/rule-sets/geoip-ru.srs"`.
- `"from"` (XDP mode only): source addresses or networks, such as LAN
  devices of a router. Such a rule has no destination items and sends the
  sources' traffic `"to"` a server's tag (everything through its tunnel),
  `"direct"` (nothing) or `"rules"` (the destination rules decide). `from`
  rules come before all destination rules; the first one containing a source
  decides. Sources no `from` rule contains, including the host itself, follow
  the destination rules. See [Router (OpenWrt)](#router-openwrt).

Each field takes one value or an array, and an entry may combine fields; it
matches when any of them does. Rules are ordered: the first entry matching a
destination address or its name decides the route, so put exceptions before
broader rules. Only the tunnels' address family is routed; IPv6 entries and
answers are ignored in IPv4 mode and vice versa. Use punycode for
internationalized names.

From a rule-set, `ip_cidr`, `domain`, `domain_suffix` and `domain_keyword`
items are used, which covers GeoIP and geosite rule-sets. Rules with
`domain_regex`, AdGuard filters, inverted or AND-combined name rules, or a port,
network, process or other condition are skipped; the client reports how many. URL rule-sets are downloaded and files read at every start, before routes change.
Each successful download is cached in `rule-sets/` beside the configuration
and used when a later download fails.

#### Domain rules and DNS

Routes see addresses, not names. When any rule contains names, the client runs
a DNS forwarder on its (first) tunnel address, port `dns.port` (default 53; UDP and TCP), and points the
system resolver at it through the (first) TUN interface: systemd-resolved on Linux
(`resolvectl`, routing domain `~.`), and the adapter's DNS server and interface
metric on Windows. These settings disappear with the interface, even if the
client crashes. Queries go to `dns.servers` (default `1.1.1.1` and `8.8.8.8`,
or Cloudflare and Google IPv6 resolvers in IPv6 mode), which are routed like
any other destination. With `"proxy"` set to a server's tag they always use
its tunnel, ahead of every rule (`true`: the default route's server, or the
first one); resolvers on private, shared (100.64.0.0/10) or
link-local addresses stay direct. Other traffic to those addresses then uses
that tunnel too. Before an answer reaches the application, each of its
addresses for a matched name gets a host route through the rule's tunnel or the
default route, unless the static routes already send it that way, so the first
connection already follows the rule. Host routes stay until the client stops.

```jsonc
"routing": {
  "default_route": "nl",
  "routes": [
    { "domain": "example.ru", "domain_suffix": ".ru", "to": "direct" },
    { "rules": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ru.srs", "to": "direct" }
  ]
},
"dns": { "servers": ["1.1.1.1", "8.8.8.8"], "set_system": true, "proxy": "nl" }
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
send queries to `<tunnel address>:<dns.port>` yourself. Another port avoids a
DNS server that binds port 53 on every address; systemd-resolved (246 and
newer) and dnsmasq take one, the Windows adapter setting needs 53.

The client turns the rules into the fewest routes: per address-space half,
each server's prefixes via its TUN device, or a `/1` via the TUN device of
the server with the most prefixes, with the other servers' prefixes and the
direct ones (via the system's preferred default route) carved out of it,
plus a physical host route to each server a tunnel route covers. Server
addresses never enter a tunnel. Large rule-sets produce thousands of routes;
they are added through netlink on Linux and the IP Helper API on Windows, and
removed on shutdown. Existing more specific system routes, such as the local
network, keep precedence. `"default_route": "direct"` with no `routes` changes
no routes at all: route traffic into the TUN devices manually. `edup-client
check` prints the resulting route counts.

### XDP mode (Linux)

`"mode": "xdp"` (default `"tun"`) needs a client built with `--features xdp`.
Instead of routes into the TUN device, eBPF programs on the network interface
of the route to the server carry the tunnel and route each destination:

- A TC egress program looks up every outgoing packet's destination in a route
  cache (up to 131072 addresses, least recently used first out). Packets to
  direct destinations continue unchanged; packets for a server are
  encapsulated in the kernel with its key and sent to it.
- An unknown destination is a route lookup: the program marks it pending and
  hands the packet to the client through the TUN device. The client decides the
  route with the same rules as TUN mode, stores it in the cache and sends the
  packet again, which now follows the stored route. Later packets to that
  destination stay in the kernel.
- An XDP program on the same interface decapsulates the servers' packets and
  passes them to the local stack as ordinary packets for the interface address.
  One UDP socket carries every tunnel; the server's address and port select
  its key.
  Interfaces without Ethernet headers, such as PPPoE (`pppoe-wan`), use TC
  programs for both directions instead; `xdp_mode` then does not apply.
- With `from` rules, a TC program on each LAN interface whose network
  contains a listed source looks it up in a permanent client table and records
  the device's mode in the top byte of the packet mark, which survives
  forwarding and masquerading. Devices of a server and direct devices need no route
  lookups; for devices following the rules, unknown destinations are looked up
  on the LAN interface, before routing, so the client re-sends the packet as
  it arrived.
- Packets follow the standard route, the one the system uses without edup,
  whenever the client fails to respond: while its heartbeat is older than 2
  seconds (the client is stopped, hung or killed), and when a lookup stays
  unanswered for 0.5 seconds, until the destination is looked up again 5
  seconds after the request. Packets never wait for the client.

Routing rules apply as in TUN mode: the first matching rule decides, otherwise
`default_route`. The servers and multicast or broadcast addresses always take the
standard route, as do destinations of the interface's other system routes, such
as the local network. Domain rules update the cache from DNS answers, including
destinations already cached. `"default_route": "direct"` without `routes` is
rejected in this mode.

```jsonc
{
  "mode": "xdp",
  "xdp_mode": "auto",   // native XDP if the driver supports it; "driver" or "skb"
  "servers": [ ... ],
  // ...the TUN mode settings; interface names have at most 14 characters
}
```

Requirements and limitations:
- Linux 5.10 or newer, root, the `veth` module, and an Ethernet, Wi-Fi or
  PPP interface. Linux 6.6
  and newer attach the TC programs as links (TCX) that disappear with the
  client. Older kernels use a `clsact` qdisc; programs left there by a crash
  only pass traffic to the standard route and are replaced at the next start.
- The TUN device `interface` still exists, without routes: it carries lookups
  and the DNS forwarder's address, for all servers. A veth pair `<interface>s`/`<interface>e`
  carries tunnelled packets, so that the kernel completes TSO/GSO segmentation
  and checksums before encapsulation. A pair left by a crash is removed at the
  next start. Native XDP may briefly reset some drivers' interfaces.
- Every server must be reached through the same interface and source
  address. Only traffic through that interface from that address is routed;
  the client prints both at start. Replies carry no local
  address, so traffic from other addresses, such as IPv6 temporary addresses,
  keeps the standard route. Restart the client after the interface's
  addresses or networks change.
- `mtu` must fit the interface MTU minus the tunnel overhead. TCP MSS is
  clamped in both directions; larger UDP and other packets to tunnelled
  destinations are dropped, not fragmented.
- As in TUN mode, existing connections to tunnelled destinations move into a
  tunnel when the client starts.
- Generic XDP (`"skb"`) and the TC decapsulation of PPP interfaces run after
  GRO, which can merge tunnel datagrams that then miss decapsulation. The
  client turns UDP GRO (`rx-gro-list`, `rx-udp-gro-forwarding`, which OpenWrt
  enables) off on the interface and the devices below it while it runs, and
  back on at exit; after a crash it stays off until a reboot.
- On interfaces without a link-layer header (PPP), decapsulated packets
  return through the veth pair, arriving on `<interface>s`: its GRO merges
  inner TCP segments, which the stack then forwards as one packet, and its
  packet steering spreads inner flows over all CPUs. Firewall rules that
  match the input interface see `<interface>s`; established connections are
  unaffected. Strict reverse path filtering (`net.ipv4.conf.all.rp_filter=1`)
  keeps the direct path.
- All tunnel packets are one flow, so one CPU receives and decapsulates them.
  When packet steering (`rps_cpus`, as set by OpenWrt's packet steering)
  sends the devices below a PPP interface to some CPUs, the client steers
  the PPP interface to the others while it runs, splitting that work.

At shutdown, and every 5 seconds with `EDUP_DIAGNOSTICS` set, the client prints
lookup and `xdp_*` packet counters.

### Router (OpenWrt)

In XDP mode on a router, `from` rules choose per LAN device:

```jsonc
"routing": {
  "default_route": "nl",
  "routes": [
    { "from": "192.168.1.50", "to": "nl" },           // always through server nl
    { "from": "192.168.1.51", "to": "de" },           // always through server de
    { "from": ["192.168.1.60", "192.168.1.61"], "to": "direct" }, // never
    { "from": "192.168.1.70", "to": "rules" },        // the rules below decide
    { "from": "192.168.1.0/24", "to": "direct" },     // other LAN devices
    { "ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], "to": "direct" },
    { "domain_suffix": ".de", "to": "de" },
    { "rules": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs", "to": "direct" }
  ]
}
```

Each tunnel carries one local address, so LAN traffic must be masqueraded on
the WAN interface, as OpenWrt's `wan` zone does by default. SIGHUP reloads the
`from` rules without a restart; other changes, including the servers, need
one. Changing a device's mode breaks its open connections that move to
another path.

Requirements and limitations:
- Flow offloading (software or hardware) must be off: offloaded connections
  bypass the egress hook. The client warns when an nftables flowtable exists.
- No other program may set the top byte of packet marks: edup stores the
  device's mode or server there.
- LAN IPv6 needs NAT66 (`masq6`); otherwise those devices keep the standard route.
- With domain rules, the client points dnsmasq at its DNS forwarder while it
  runs (`edup.conf` in dnsmasq's `conf-dir`) and restores it at exit. After a
  crash, the next start, or stopping the service, removes the leftover file.
  dnsmasq binds port 53 on every new address, the tunnel's included, so the
  package runs the forwarder on port 10053 (uci `dns_port`).
- The router's own DNS queries follow the rules like its other traffic. ISP
  resolvers often refuse queries arriving from the tunnel server's address; the
  client warns when dnsmasq's upstream servers would be tunnelled. Add a direct
  rule for them or use public resolvers.

#### OpenWrt packages

OpenWrt 25.12 and newer on aarch64 (tested on mediatek/filogic). Build a static
executable with [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild),
zig 0.15.2 and the eBPF toolchain above; with an OpenWrt SDK, also the
`edup-client` and `luci-app-edup` apk packages:

```sh
rustup target add --toolchain stable aarch64-unknown-linux-musl
cargo install --locked cargo-zigbuild
SDK=~/openwrt/openwrt-sdk-25.12.2-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64 sh scripts/build-openwrt.sh
```

Output: `dist/openwrt/`. The CI job `openwrt` builds the same archive. Install
on the router (the packages are unsigned):

```sh
apk add --allow-untrusted edup-client-0.2.0-r3.apk luci-app-edup-0.2.0-r2.apk
```

Then use **Services → edup VPN** in LuCI: tunnel servers and their
credentials on *Servers*, per-device modes (a server, the traffic rules, or no
VPN) on *Devices*, destination rules on *Traffic rules*, and status and
tunnel settings on *Settings*. *Traffic rules* also uploads `.srs` rule-set
files to `/etc/edup/rule-sets/`, which firmware upgrades keep: the upload
button in a rule's dialog adds the file to that rule, and the list below the
rules shows which rules use each file. A replaced file takes effect when the
service restarts. The settings live in `/etc/config/edup`, one
`config server '<tag>'` section per server; the service writes
`/var/etc/edup/client.json` from them. A disabled server's devices and rules
go direct. Device changes apply through SIGHUP, others restart the service, as
does a WAN reconnect (`wan_interface`), since PPPoE may assign a new address.
For PPPoE (MTU 1492) set `mtu` to 1465. Upgrading from 0.1 moves the server
to a section named `vpn` and renames `proxy`/`all` to `vpn` and
`bypass`/`off` to `direct`.

### IPv6

IPv6 is a separate tunnel mode: IPv6 packets travel over IPv6 UDP; IPv4 packets
travel over IPv4 UDP. The client's server addresses select the mode. Only that
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
  "servers": [
    { "tag": "v6", "server": "[2001:db8::1]:7777", "user": 4829017365182049271, "password": "replace-this-password" }
  ],
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
