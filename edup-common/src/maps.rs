//! Структуры BPF-карт, общие для XDP-программы и загрузчика.
//!
//! Соглашение по порядку байт: поля с суффиксом `_be` хранятся так, как лежат в
//! пакете (network order, прочитаны «как есть»), остальные — в host order.

pub const MAX_USERS: u32 = 65536;
pub const NAT_ENTRIES: u32 = 262_144;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;

/// Глобальная конфигурация: единственный элемент карты `CONFIG`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Config {
    /// Адрес, на который приходят туннельные пакеты.
    pub server_ip_be: u32,
    /// Внешний адрес NAT (обычно совпадает с `server_ip_be`).
    pub nat_ip_be: u32,
    pub port_be: u16,
    pub nat_port_min: u16,
    pub nat_port_max: u16,
    /// Maximum outer IP packet size (egress interface MTU).
    pub max_frame: u16,
    /// All-zero addresses disable the corresponding IPv6 feature.
    pub server_ip6: [u8; 16],
    pub nat_ip6: [u8; 16],
    /// Optional next-hop MAC overrides; zero uses the learned upstream MAC.
    pub gateway_mac: [u8; 6],
    pub gateway6_mac: [u8; 6],
    pub _pad: [u8; 4],
}

/// Replaced atomically in ENDPOINTS so address, port and link-layer route agree.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Endpoint {
    pub address: [u8; 16],
    pub mac: [u8; 12],
    pub port_be: u16,
    pub v6: u8,
    pub _pad: u8,
}

/// USERS is indexed by the internal 16-bit user index (config position + 1).
/// USER_IDS maps the public signed 64-bit ID to this array index.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct User {
    pub id: i64,
    pub key0: u64,
    pub key1: u64,
    /// Последний адрес клиента: `ip_be | port_be << 32`; 0 — ещё неизвестен.
    pub endpoint: u64,
    pub last_seen_ns: u64,
    pub enabled: u32,
    pub _pad: u32,
}

impl User {
    #[inline(always)]
    pub const fn pack_endpoint(ip_be: u32, port_be: u16) -> u64 {
        ip_be as u64 | (port_be as u64) << 32
    }

    #[inline(always)]
    pub const fn endpoint_ip_be(ep: u64) -> u32 {
        ep as u32
    }

    #[inline(always)]
    pub const fn endpoint_port_be(ep: u64) -> u16 {
        (ep >> 32) as u16
    }
}

/// Ключ исходящей трансляции (endpoint-independent mapping, RFC 4787):
/// Both families use (user, port, protocol, family); local addresses are omitted.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NatOutKey {
    /// Порт TCP/UDP или идентификатор ICMP echo.
    pub inner_port_be: u16,
    pub proto: u8,
    /// 0 for IPv4, 1 for IPv6.
    pub v6: u8,
    pub user: u16,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NatOutVal {
    pub pub_port_be: u16,
    pub _pad: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NatInKey {
    pub pub_port_be: u16,
    pub proto: u8,
    pub v6: u8,
}

/// Каноническая запись трансляции: здесь живут время и состояние.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NatInVal {
    pub last_seen_ns: u64,
    pub inner_port_be: u16,
    pub user: u16,
    pub state: u8,
    pub _pad: [u8; 3],
}

pub const ST_OTHER: u8 = 0;
pub const ST_TCP_SYN: u8 = 1;
pub const ST_TCP_EST: u8 = 2;
pub const ST_TCP_CLOSING: u8 = 3;

const SEC: u64 = 1_000_000_000;

/// Таймаут бездействия записи NAT в наносекундах.
#[inline(always)]
pub const fn nat_timeout_ns(proto: u8, state: u8) -> u64 {
    match (proto, state) {
        (IPPROTO_TCP, ST_TCP_EST) => 7440 * SEC,
        (IPPROTO_TCP, ST_TCP_SYN) => 60 * SEC,
        (IPPROTO_TCP, _) => 60 * SEC,
        (IPPROTO_UDP, _) => 180 * SEC,
        _ => 30 * SEC,
    }
}

/// Как часто обновлять `last_seen` (реже — меньше гонок кеш-линий между CPU).
pub const TOUCH_INTERVAL_NS: u64 = SEC;

/// Индексы счётчиков в per-CPU карте `STATS`.
pub mod stat {
    pub const RX_TUNNEL: u32 = 0;
    pub const TX_INTERNET: u32 = 1;
    pub const RX_INTERNET: u32 = 2;
    pub const TX_TUNNEL: u32 = 3;
    pub const KEEPALIVE: u32 = 4;
    pub const DROP_BAD_HDR: u32 = 5;
    pub const DROP_UNKNOWN_USER: u32 = 6;
    pub const DROP_BAD_INNER: u32 = 7;
    pub const DROP_SPOOF: u32 = 8;
    pub const DROP_PROTO: u32 = 9;
    pub const DROP_TTL: u32 = 10;
    pub const DROP_NAT_FULL: u32 = 11;
    pub const DROP_NO_ENDPOINT: u32 = 12;
    pub const DROP_TOO_BIG: u32 = 13;
    pub const DROP_ADJUST: u32 = 14;
    pub const PASS: u32 = 15;
    pub const COUNT: u32 = 16;

    pub const NAMES: [&str; COUNT as usize] = [
        "rx_tunnel",
        "tx_internet",
        "rx_internet",
        "tx_tunnel",
        "keepalive",
        "drop_bad_hdr",
        "drop_unknown_user",
        "drop_bad_inner",
        "drop_spoof",
        "drop_proto",
        "drop_ttl",
        "drop_nat_full",
        "drop_no_endpoint",
        "drop_too_big",
        "drop_adjust",
        "pass",
    ];
}

/// Linux client XDP mode: the single element of `CLIENT_CONFIG`.
/// Addresses use the first four bytes for IPv4.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ClientConfig {
    pub key0: u64,
    pub key1: u64,
    pub user: i64,
    /// Source address of proxied traffic: the physical route's address.
    pub local: [u8; 16],
    pub server: [u8; 16],
    pub server_port_be: u16,
    /// Port of the client's UDP socket, shared by keepalives and the datapath.
    pub local_port_be: u16,
    /// Largest inner packet carried through the tunnel.
    pub mtu: u16,
    pub v6: u8,
    pub _pad: u8,
    /// Physical interface: XDP ingress, TC egress and tunnel output.
    pub physical: u32,
    /// Veth whose disabled offloads make the kernel finish GSO and checksums.
    pub segment: u32,
    /// TUN device carrying route lookups to userspace.
    pub tun: u32,
    /// Marks packets re-injected by userspace and encapsulated packets.
    pub mark: u32,
}

/// `ROUTES` values, keyed by a 16-byte destination address.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RouteEntry {
    /// ROUTE_PENDING: time of the lookup request.
    pub since_ns: u64,
    pub action: u32,
    pub _pad: u32,
}

pub const ROUTE_PENDING: u32 = 0;
pub const ROUTE_PROXY: u32 = 1;
pub const ROUTE_BYPASS: u32 = 2;

pub const ROUTE_ENTRIES: u32 = 131_072;
/// Userspace refreshes `HEARTBEAT`; older heartbeats mean it stopped responding.
pub const HEARTBEAT_TIMEOUT_NS: u64 = 2 * SEC;
/// A lookup unanswered for this long sends the destination the standard route,
pub const LOOKUP_WAIT_NS: u64 = SEC / 2;
/// until it is asked again.
pub const LOOKUP_RETRY_NS: u64 = 5 * SEC;
/// Default packet mark; any value works if policy routing does not use it.
pub const CLIENT_MARK: u32 = 0x6564_7570;

/// Indexes of the per-CPU client counters in `CLIENT_STATS`.
pub mod client_stat {
    pub const PROXY: u32 = 0;
    pub const BYPASS: u32 = 1;
    pub const LOOKUP: u32 = 2;
    pub const FALLBACK: u32 = 3;
    pub const TX_TUNNEL: u32 = 4;
    pub const RX_TUNNEL: u32 = 5;
    pub const DROP_UNSUPPORTED: u32 = 6;
    pub const DROP_TOO_BIG: u32 = 7;
    pub const DROP_BAD: u32 = 8;
    pub const DROP_ADJUST: u32 = 9;
    pub const COUNT: u32 = 10;

    pub const NAMES: [&str; COUNT as usize] = [
        "xdp_proxy",
        "xdp_bypass",
        "xdp_lookup",
        "xdp_fallback",
        "xdp_tx_tunnel",
        "xdp_rx_tunnel",
        "xdp_drop_unsupported",
        "xdp_drop_too_big",
        "xdp_drop_bad",
        "xdp_drop_adjust",
    ];
}

#[cfg(feature = "aya")]
mod pod {
    use super::*;
    unsafe impl aya::Pod for Config {}
    unsafe impl aya::Pod for Endpoint {}
    unsafe impl aya::Pod for User {}
    unsafe impl aya::Pod for NatOutKey {}
    unsafe impl aya::Pod for NatOutVal {}
    unsafe impl aya::Pod for NatInKey {}
    unsafe impl aya::Pod for NatInVal {}
    unsafe impl aya::Pod for ClientConfig {}
    unsafe impl aya::Pod for RouteEntry {}
}

const _: () = {
    assert!(core::mem::size_of::<Config>() == 64);
    assert!(core::mem::size_of::<Endpoint>() == 32);
    assert!(core::mem::size_of::<User>() == 48);
    assert!(core::mem::size_of::<NatOutKey>() == 8);
    assert!(core::mem::size_of::<NatInKey>() == 4);
    assert!(core::mem::size_of::<NatInVal>() == 16);
    assert!(core::mem::size_of::<ClientConfig>() == 80);
    assert!(core::mem::size_of::<RouteEntry>() == 16);
};
