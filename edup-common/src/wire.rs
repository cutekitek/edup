//! Формат пакета edup и обфускация.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +---------------------------------------------------------------+
//! |                  Nonce (32, открытый, случайный)              |
//! +---------------+---------------+-------------------------------+
//! |  Type | Flags |  Magic 0xED   |          User ID (BE)         |  ← XOR
//! +---------------+---------------+-------------------------------+
//! |               Внутренний IPv4-пакет как есть                  |  ← XOR
//! ```
//!
//! Всё после nonce («область») XOR-ится с потоком ключа: слово `i` потока —
//! `ks_word(seed, i)`, байты слова берутся в little-endian. Слова независимы
//! (counter mode), поэтому их удобно считать в ограниченном цикле eBPF.

/// Длина nonce в начале UDP-полезной нагрузки.
pub const NONCE_LEN: usize = 4;
/// Полный служебный заголовок: nonce + обфусцированные 4 байта.
pub const HDR_LEN: usize = 8;
/// Накладные расходы на внешний IPv4 + UDP + заголовок edup.
pub const OVERHEAD_V4: usize = 20 + 8 + HDR_LEN;
/// IPv6 + UDP + edup header.
pub const OVERHEAD_V6: usize = 40 + 8 + HDR_LEN;

pub const MAGIC: u8 = 0xED;

pub const TYPE_DATA: u8 = 0;
/// Клиент шлёт раз в N секунд; сервер отвечает таким же пакетом.
pub const TYPE_KEEPALIVE: u8 = 1;

/// Максимум 8-байтных слов потока ключа на пакет. Покрывает область до 1536 байт,
/// то есть внешний MTU 1500 с запасом. Ограничение нужно верификатору.
pub const MAX_KS_WORDS: u32 = 192;

const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;

/// 128-битный ключ, выведенный из пароля (см. [`crate::key`]).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Key {
    pub k0: u64,
    pub k1: u64,
}

/// Финализатор SplitMix64.
#[inline(always)]
pub const fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Начальное состояние потока ключа для пакета с данным nonce.
#[inline(always)]
pub const fn ks_seed(key: &Key, nonce: u32) -> u64 {
    key.k0 ^ mix64(key.k1 ^ nonce as u64)
}

/// Слово `i` потока ключа.
#[inline(always)]
pub const fn ks_word(seed: u64, i: u32) -> u64 {
    mix64(seed.wrapping_add((i as u64 + 1).wrapping_mul(GOLDEN)))
}

/// Открытые 4 байта заголовка после nonce как u32 в little-endian раскладке
/// (так их видит eBPF при чтении `*const u32` из пакета).
#[inline(always)]
pub const fn hdr_word(typ: u8, user: u16) -> u32 {
    let u = user.to_be_bytes();
    u32::from_le_bytes([typ, MAGIC, u[0], u[1]])
}

/// Разбор открытых 4 байт заголовка: `(type, flags, user)`, если magic верен.
#[inline(always)]
pub const fn parse_hdr_word(w: u32) -> Option<(u8, u8, u16)> {
    let b = w.to_le_bytes();
    if b[1] != MAGIC {
        return None;
    }
    Some((b[0] & 0x0f, b[0] >> 4, u16::from_be_bytes([b[2], b[3]])))
}

/// XOR области (всё после nonce) с потоком ключа. Операция обратима.
pub fn xor_region(key: &Key, nonce: u32, region: &mut [u8]) {
    let seed = ks_seed(key, nonce);
    let (chunks, tail) = region.as_chunks_mut::<8>();
    let full = chunks.len();
    for (i, chunk) in chunks.iter_mut().enumerate() {
        // Fixed-size loads let LLVM use a word XOR instead of a partial-byte
        // loop. Byte-array loads/stores also work on unaligned buffers.
        let value = u64::from_le_bytes(*chunk);
        *chunk = (value ^ ks_word(seed, i as u32)).to_le_bytes();
    }
    if !tail.is_empty() {
        let ks = ks_word(seed, full as u32).to_le_bytes();
        for (b, k) in tail.iter_mut().zip(ks) {
            *b ^= k;
        }
    }
}

/// Собирает пакет на месте: `pkt[..HDR_LEN]` — место под заголовок,
/// `pkt[HDR_LEN..]` — уже положенный внутренний пакет.
pub fn seal(key: &Key, nonce: u32, typ: u8, user: u16, pkt: &mut [u8]) {
    debug_assert!(pkt.len() >= HDR_LEN);
    pkt[..NONCE_LEN].copy_from_slice(&nonce.to_le_bytes());
    pkt[NONCE_LEN..HDR_LEN].copy_from_slice(&hdr_word(typ, user).to_le_bytes());
    xor_region(key, nonce, &mut pkt[NONCE_LEN..]);
}

/// Результат [`open`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opened {
    pub typ: u8,
    pub flags: u8,
    pub user: u16,
}

/// Деобфусцирует пакет на месте. Полезная нагрузка — `pkt[HDR_LEN..]`.
/// Возвращает `None` для мусора (короткий пакет или неверный magic);
/// в этом случае содержимое буфера не определено.
pub fn open(key: &Key, pkt: &mut [u8]) -> Option<Opened> {
    if pkt.len() < HDR_LEN {
        return None;
    }
    let nonce = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
    xor_region(key, nonce, &mut pkt[NONCE_LEN..]);
    let w = u32::from_le_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
    let (typ, flags, user) = parse_hdr_word(w)?;
    Some(Opened { typ, flags, user })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: Key = Key {
        k0: 0x0123_4567_89ab_cdef,
        k1: 0xfedc_ba98_7654_3210,
    };

    #[test]
    fn word_xor_matches_original_wire_at_every_length_and_alignment() {
        // A roundtrip alone could hide a change made to both seal and open.
        // Compare against the original byte implementation, including tails.
        for offset in 0..8 {
            for len in 0..=MAX_KS_WORDS as usize * 8 {
                let mut actual = [0xa5; MAX_KS_WORDS as usize * 8 + 16];
                let mut expected = actual;
                let nonce = (len as u32).wrapping_mul(0x9e3779b9) ^ offset as u32;
                let seed = ks_seed(&KEY, nonce);
                for (i, b) in expected[offset..offset + len].iter_mut().enumerate() {
                    *b ^= (ks_word(seed, (i / 8) as u32) >> ((i % 8) * 8)) as u8;
                }
                xor_region(&KEY, nonce, &mut actual[offset..offset + len]);
                assert_eq!(actual, expected, "offset={offset}, len={len}");
            }
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        for len in [0usize, 1, 7, 8, 9, 20, 1464] {
            let payload: [u8; 1464] = core::array::from_fn(|i| (i * 7) as u8);
            let mut buf = [0u8; HDR_LEN + 1464];
            buf[HDR_LEN..HDR_LEN + len].copy_from_slice(&payload[..len]);
            let pkt = &mut buf[..HDR_LEN + len];
            seal(&KEY, 0xdead_beef, TYPE_DATA, 0x0102, pkt);
            if len >= 16 {
                assert_ne!(
                    &pkt[HDR_LEN..],
                    &payload[..len],
                    "payload must be scrambled"
                );
            }
            let o = open(&KEY, pkt).expect("valid packet");
            assert_eq!(
                o,
                Opened {
                    typ: TYPE_DATA,
                    flags: 0,
                    user: 0x0102
                }
            );
            assert_eq!(&pkt[HDR_LEN..], &payload[..len]);
        }
    }

    #[test]
    fn wrong_key_is_rejected() {
        let mut pkt = [0u8; HDR_LEN + 20];
        seal(&KEY, 1, TYPE_KEEPALIVE, 7, &mut pkt);
        let other = Key { k0: 1, k1: 2 };
        // magic совпадёт случайно с вероятностью 1/256; для этого nonce — нет.
        assert!(open(&other, &mut pkt).is_none());
    }

    #[test]
    fn keystream_differs_per_nonce() {
        let a = ks_word(ks_seed(&KEY, 1), 0);
        let b = ks_word(ks_seed(&KEY, 2), 0);
        assert_ne!(a, b);
    }
}
