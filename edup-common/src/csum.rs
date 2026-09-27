//! Контрольные суммы Internet checksum (RFC 1071 / RFC 1624).
//!
//! Все значения — «сырые» u16/u32 как они лежат в памяти пакета. Сумма в
//! дополнительном коде не зависит от порядка байт, если все операнды взяты
//! одинаково, поэтому переводить в host order не нужно.

#[inline(always)]
pub const fn fold(mut sum: u64) -> u16 {
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum as u16
}

/// Инкрементальное обновление при замене 16-битного поля (RFC 1624, eqn. 3).
#[inline(always)]
pub const fn replace2(check: u16, old: u16, new: u16) -> u16 {
    let sum = (!check as u64) + (!old as u64 & 0xffff) + new as u64;
    !fold(sum)
}

/// Инкрементальное обновление при замене 32-битного поля.
#[inline(always)]
pub const fn replace4(check: u16, old: u32, new: u32) -> u16 {
    let sum = (!check as u64)
        + (!(old as u16) as u64)
        + (!((old >> 16) as u16) as u64)
        + (new as u16 as u64)
        + ((new >> 16) as u16 as u64);
    !fold(sum)
}

/// То же для UDP: 0 означает «без контрольной суммы» и не трогается,
/// а вычисленный 0 передаётся как 0xffff.
#[inline(always)]
pub const fn udp_replace4(check: u16, old: u32, new: u32) -> u16 {
    if check == 0 {
        return 0;
    }
    let c = replace4(check, old, new);
    if c == 0 { 0xffff } else { c }
}

#[inline(always)]
pub const fn udp_replace2(check: u16, old: u16, new: u16) -> u16 {
    if check == 0 {
        return 0;
    }
    let c = replace2(check, old, new);
    if c == 0 { 0xffff } else { c }
}

/// Полная сумма 20-байтного IPv4-заголовка (поле check должно быть 0).
#[inline(always)]
pub const fn ipv4_header(words: &[u16; 10]) -> u16 {
    let mut sum = 0u64;
    let mut i = 0;
    while i < 10 {
        sum += words[i] as u64;
        i += 1;
    }
    !fold(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full(words: &[u16]) -> u16 {
        !fold(words.iter().map(|&w| w as u64).sum())
    }

    #[test]
    fn incremental_matches_full() {
        let mut w = [
            0x4500u16, 0x0073, 0x0000, 0x4000, 0x4011, 0, 0xc0a8, 0x0001, 0xc0a8, 0x00c7,
        ];
        let c = full(&w);
        w[5] = c;
        assert_eq!(full(&w), 0);

        // Меняем src IP целиком (два слова) инкрементально.
        let old = (w[7] as u32) << 16 | w[6] as u32;
        let new = 0x0a42_0005u32;
        let c2 = replace4(c, old, new);
        w[6] = new as u16;
        w[7] = (new >> 16) as u16;
        w[5] = 0;
        assert_eq!(c2, full(&w));

        // TTL-- (слово ttl|proto).
        let old_w = w[4];
        w[4] -= 0x0100;
        assert_eq!(replace2(c2, old_w, w[4]), full(&w));
    }

    #[test]
    fn ipv4_header_known_vector() {
        // Пример из Wikipedia: результат 0xb861.
        let w = [
            0x4500, 0x0073, 0x0000, 0x4000, 0x4011, 0x0000, 0xc0a8, 0x0001, 0xc0a8, 0x00c7,
        ];
        assert_eq!(ipv4_header(&w), 0xb861);
    }
}
