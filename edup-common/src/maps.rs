//! Структуры BPF-карт, общие для XDP-программы и загрузчика.
//!
//! Соглашение по порядку байт: поля с суффиксом `_be` хранятся так, как лежат в
//! пакете (network order, прочитаны «как есть»), остальные — в host order.

pub const MAX_USERS: u32 = 65536;
pub const NAT_ENTRIES: u32 = 262_144;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// Глобальная конфигурация: единственный элемент карты `CONFIG`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Config {
    pub key0: u64,
    pub key1: u64,
    /// Адрес, на который приходят туннельные пакеты.
    pub server_ip_be: u32,
    /// Внешний адрес NAT (обычно совпадает с `server_ip_be`).
    pub nat_ip_be: u32,
    /// Сеть туннеля, host order, например 10.66.0.0.
    pub tun_net: u32,
    /// Маска сети туннеля, host order. Префикс не длиннее /16.
    pub tun_mask: u32,
    pub port_be: u16,
    pub nat_port_min: u16,
    pub nat_port_max: u16,
    /// Максимальная длина внешнего IPv4-пакета (MTU исходящего интерфейса).
    pub max_frame: u16,
}

/// Значение карты `USERS`, индекс — ID пользователя.
/// Туннельный адрес пользователя всегда `tun_net + id`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct User {
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
/// один внутренний (ip, port) — один внешний порт для любых адресатов.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NatOutKey {
    pub inner_ip_be: u32,
    /// Порт TCP/UDP или идентификатор ICMP echo.
    pub inner_port_be: u16,
    pub proto: u8,
    pub _pad: u8,
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
    pub _pad: u8,
}

/// Каноническая запись трансляции: здесь живут время и состояние.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NatInVal {
    pub last_seen_ns: u64,
    pub inner_ip_be: u32,
    pub inner_port_be: u16,
    pub user: u16,
    pub state: u8,
    pub _pad: [u8; 7],
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

#[cfg(feature = "aya")]
mod pod {
    use super::*;
    unsafe impl aya::Pod for Config {}
    unsafe impl aya::Pod for User {}
    unsafe impl aya::Pod for NatOutKey {}
    unsafe impl aya::Pod for NatOutVal {}
    unsafe impl aya::Pod for NatInKey {}
    unsafe impl aya::Pod for NatInVal {}
}

const _: () = {
    assert!(core::mem::size_of::<Config>() == 40);
    assert!(core::mem::size_of::<User>() == 24);
    assert!(core::mem::size_of::<NatOutKey>() == 8);
    assert!(core::mem::size_of::<NatInKey>() == 4);
    assert!(core::mem::size_of::<NatInVal>() == 24);
};
