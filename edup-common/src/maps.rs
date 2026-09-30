//! Структуры BPF-карт, общие для XDP-программы и загрузчика.
//!
//! Соглашение по порядку байт: поля с суффиксом `_be` хранятся так, как лежат в
//! пакете (network order, прочитаны «как есть»), остальные — в host order.

pub const MAX_USERS: u32 = 65536;
pub const NAT_ENTRIES: u32 = 262_144;
/// Two session slots (key phases 0 and 1) per user index. The loader shrinks
/// the SESSIONS map to the configured users; this is the compiled maximum.
pub const MAX_SESSIONS: u32 = MAX_USERS * 2;

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
    /// Random per load: first half of every server handshake nonce, so session
    /// keys from before a reload can never be derived again.
    pub salt: u64,
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
    /// Long-term key derived from the password; only used as an HChaCha20 key.
    pub key: [u32; 8],
    /// Последний адрес клиента: `ip_be | port_be << 32`; 0 — ещё неизвестен.
    pub endpoint: u64,
    pub last_seen_ns: u64,
    /// Handshakes answered since load: second half of the server nonce.
    pub handshakes: u64,
    pub enabled: u32,
    /// Phase of the active session slot. A handshake fills the other slot.
    pub phase: u32,
}

pub const SESSION_EMPTY: u64 = 0;
pub const SESSION_PENDING: u64 = 1;
pub const SESSION_ACTIVE: u64 = 2;
/// Replay window: 64 slots of 16 counters (see `crypto::replay_update`).
pub const WINDOW_SLOTS: usize = 64;

/// SESSIONS entry `user * 2 + phase`. Updates are not atomic as a whole: a
/// torn key fails authentication, so every race fails closed.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Session {
    pub key: [u32; 8],
    /// Next server-to-client counter; counter 0 sealed the RESPONSE.
    pub tx: u64,
    pub state: u64,
    /// Highest client counter accepted. Only a packet that raises it may move
    /// the learned endpoint, so a delayed packet cannot redirect replies.
    pub newest: u64,
    pub window: [u64; WINDOW_SLOTS],
}

impl Default for Session {
    fn default() -> Self {
        Self {
            key: [0; 8],
            tx: 0,
            state: SESSION_EMPTY,
            newest: 0,
            window: [0; WINDOW_SLOTS],
        }
    }
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

/// SplitMix64 finalizer: spreads NAT port probes (not a cryptographic hash).
#[inline(always)]
pub const fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Как часто обновлять `last_seen` (реже — меньше гонок кеш-линий между CPU).
pub const TOUCH_INTERVAL_NS: u64 = SEC;

/// Slots of the PROTOCOLS program array. The dispatcher tail-calls a family's
/// data path. Cryptography runs in its own tail-called programs, each starting
/// with a fresh 512-byte stack: the data path's frame leaves too little room.
pub mod program {
    pub const IPV4: u32 = 0;
    pub const IPV6: u32 = 1;
    /// INIT → RESPONSE.
    pub const HANDSHAKE_IPV4: u32 = 2;
    pub const HANDSHAKE_IPV6: u32 = 3;
    /// Decrypt and verify, then continue in ACCEPT_*.
    pub const OPEN: u32 = 4;
    /// Encrypt, finish the outer checksum and transmit.
    pub const SEAL: u32 = 5;
    /// Replay check, session confirmation, endpoint learning, NAT.
    pub const ACCEPT_IPV4: u32 = 6;
    pub const ACCEPT_IPV6: u32 = 7;
    pub const COUNT: u32 = 8;
    pub const NAMES: [&str; COUNT as usize] = [
        "edup_ipv4",
        "edup_ipv6",
        "edup_handshake_ipv4",
        "edup_handshake_ipv6",
        "edup_open",
        "edup_seal",
        "edup_accept_ipv4",
        "edup_accept_ipv6",
    ];
}

/// Индексы счётчиков в per-CPU карте `STATS`.
pub mod stat {
    pub const RX_TUNNEL: u32 = 0;
    pub const TX_INTERNET: u32 = 1;
    pub const RX_INTERNET: u32 = 2;
    pub const TX_TUNNEL: u32 = 3;
    pub const KEEPALIVE: u32 = 4;
    pub const HANDSHAKE: u32 = 5;
    pub const DROP_BAD_HDR: u32 = 6;
    pub const DROP_UNKNOWN_USER: u32 = 7;
    pub const DROP_AUTH: u32 = 8;
    pub const DROP_REPLAY: u32 = 9;
    pub const DROP_NO_SESSION: u32 = 10;
    pub const DROP_BAD_INNER: u32 = 11;
    pub const DROP_SPOOF: u32 = 12;
    pub const DROP_PROTO: u32 = 13;
    pub const DROP_TTL: u32 = 14;
    pub const DROP_NAT_FULL: u32 = 15;
    pub const DROP_NO_ENDPOINT: u32 = 16;
    pub const DROP_TOO_BIG: u32 = 17;
    pub const DROP_ADJUST: u32 = 18;
    pub const PASS: u32 = 19;
    pub const COUNT: u32 = 20;

    pub const NAMES: [&str; COUNT as usize] = [
        "rx_tunnel",
        "tx_internet",
        "rx_internet",
        "tx_tunnel",
        "keepalive",
        "handshake",
        "drop_bad_hdr",
        "drop_unknown_user",
        "drop_auth",
        "drop_replay",
        "drop_no_session",
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

#[cfg(feature = "aya")]
mod pod {
    use super::*;
    unsafe impl aya::Pod for Config {}
    unsafe impl aya::Pod for Endpoint {}
    unsafe impl aya::Pod for User {}
    unsafe impl aya::Pod for Session {}
    unsafe impl aya::Pod for NatOutKey {}
    unsafe impl aya::Pod for NatOutVal {}
    unsafe impl aya::Pod for NatInKey {}
    unsafe impl aya::Pod for NatInVal {}
}

const _: () = {
    assert!(core::mem::size_of::<Config>() == 72);
    assert!(core::mem::size_of::<Endpoint>() == 32);
    assert!(core::mem::size_of::<User>() == 72);
    assert!(core::mem::size_of::<Session>() == 56 + WINDOW_SLOTS * 8);
    assert!(core::mem::size_of::<NatOutKey>() == 8);
    assert!(core::mem::size_of::<NatInKey>() == 4);
    assert!(core::mem::size_of::<NatInVal>() == 16);
};
