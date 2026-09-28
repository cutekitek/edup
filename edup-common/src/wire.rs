//! Wire v4: [8-byte signed user ID, big-endian][XOR type + payload].
//! Type 0: compact IPv4, type 1: keepalive, type 2: compact IPv6.
//! Compact IP omits the local address; its L4 checksum assumes address zero.
//! There is no nonce; the repeating XOR stream is obfuscation, not authentication.

pub const USER_ID_LEN: usize = 8;
pub const CONTROL_LEN: usize = 1;
pub const HDR_LEN: usize = USER_ID_LEN + CONTROL_LEN;
pub const IPV4_META_LEN: usize = 10;
pub const IPV4_SAVING: usize = 20 - IPV4_META_LEN;
/// Outer IPv4 + UDP + wire header minus omitted inner IPv4 bytes.
pub const OVERHEAD_V4: usize = 20 + 8 + HDR_LEN - IPV4_SAVING;
pub const IPV6_META_LEN: usize = 22;
pub const IPV6_SAVING: usize = 40 - IPV6_META_LEN;
pub const OVERHEAD_V6: usize = 40 + 8 + HDR_LEN - IPV6_SAVING;

pub const TYPE_DATA: u8 = 0;
pub const TYPE_KEEPALIVE: u8 = 1;
pub const TYPE_IPV6: u8 = 2;

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

/// Fixed password-derived stream seed.
#[inline(always)]
pub const fn ks_seed(key: &Key) -> u64 {
    key.k0 ^ mix64(key.k1)
}

/// Слово `i` потока ключа.
#[inline(always)]
pub const fn ks_word(seed: u64, i: u32) -> u64 {
    mix64(seed.wrapping_add((i as u64 + 1).wrapping_mul(GOLDEN)))
}

/// Read the public routing ID without touching the XOR region.
pub fn user_id(pkt: &[u8]) -> Option<i64> {
    Some(i64::from_be_bytes(pkt.get(..USER_ID_LEN)?.try_into().ok()?))
}

/// Reversible XOR using the same password-derived stream for every packet.
pub fn xor_region(key: &Key, region: &mut [u8]) {
    let seed = ks_seed(key);
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

/// Seal an already encoded body at `pkt[HDR_LEN..]` with a one-byte type.
/// Use `seal_data` to compact a complete IP packet first.
pub fn seal(key: &Key, typ: u8, user: i64, pkt: &mut [u8]) {
    assert!(pkt.len() >= HDR_LEN);
    pkt[..USER_ID_LEN].copy_from_slice(&user.to_be_bytes());
    pkt[USER_ID_LEN] = typ;
    xor_region(key, &mut pkt[USER_ID_LEN..]);
}

/// Decoded control header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opened {
    pub typ: u8,
    pub flags: u8,
    pub user: i64,
}

/// Деобфусцирует пакет на месте. Полезная нагрузка — `pkt[HDR_LEN..]`.
/// Returns `None` for truncated packets or unknown types;
/// в этом случае содержимое буфера не определено.
pub fn open(key: &Key, pkt: &mut [u8]) -> Option<Opened> {
    if pkt.len() < HDR_LEN {
        return None;
    }
    let user = user_id(pkt)?;
    xor_region(key, &mut pkt[USER_ID_LEN..]);
    let typ = pkt[USER_ID_LEN];
    if typ > TYPE_IPV6 {
        return None;
    }
    let flags = 0;
    Some(Opened { typ, flags, user })
}

/// Pack and seal an IP packet already placed at `pkt[HDR_LEN..]`.
/// Returns the datagram length. IPv4 loses 10 bytes; IPv6 loses 18 bytes.
/// `to_server` chooses which address is local (source outbound, destination inbound).
pub fn seal_data(key: &Key, user: i64, pkt: &mut [u8], to_server: bool) -> Option<usize> {
    let ip = pkt.get_mut(HDR_LEN..)?;
    let typ = match ip.first()? >> 4 {
        4 => {
            if ip.len() < 20 || u16::from_be_bytes([ip[2], ip[3]]) as usize != ip.len() {
                return None;
            }
            let ihl = (ip[0] & 15) as usize * 4;
            if ihl < 20 || ihl > ip.len() || u16::from_be_bytes([ip[6], ip[7]]) & 0xbfff != 0 {
                return None;
            }
            let local = if to_server { 12 } else { 16 };
            let old = u32::from_ne_bytes(ip[local..local + 4].try_into().ok()?);
            replace_local_checksum(ip, ihl, old, 0)?;
            let peer = if to_server { 16 } else { 12 };
            // Flags use the top three bits; spare low bits carry the option-word count.
            let meta = [
                ip[peer],
                ip[peer + 1],
                ip[peer + 2],
                ip[peer + 3],
                ip[4],
                ip[5],
                (ip[6] & 0xe0) | ((ihl / 4 - 5) as u8),
                ip[1],
                ip[8],
                ip[9],
            ];
            ip.copy_within(20.., IPV4_META_LEN);
            ip[..IPV4_META_LEN].copy_from_slice(&meta);
            TYPE_DATA
        }
        6 => {
            if ip.len() < 40 || u16::from_be_bytes([ip[4], ip[5]]) as usize + 40 != ip.len() {
                return None;
            }
            let offset = if to_server { 8 } else { 24 };
            let old: [u8; 16] = ip[offset..offset + 16].try_into().ok()?;
            replace_local_checksum6(ip, &old, &[0; 16])?;
            let peer = if to_server { 24 } else { 8 };
            let address: [u8; 16] = ip[peer..peer + 16].try_into().ok()?;
            let fields = [ip[0] & 15, ip[1], ip[2], ip[3], ip[6], ip[7]];
            ip.copy_within(40.., IPV6_META_LEN);
            ip[..16].copy_from_slice(&address);
            ip[16..22].copy_from_slice(&fields);
            TYPE_IPV6
        }
        _ => return None,
    };
    let len = pkt.len()
        - if typ == TYPE_DATA {
            IPV4_SAVING
        } else {
            IPV6_SAVING
        };
    seal(key, typ, user, &mut pkt[..len]);
    Some(len)
}

/// Reconstruct the decrypted payload. The local address is supplied by the
/// receiver: zero on the server, the configured TUN address on the client.
/// IPv4 options are preserved; fragments remain unsupported.
pub fn unpack(
    typ: u8,
    body: &[u8],
    out: &mut [u8],
    local: &[u8],
    to_server: bool,
) -> Option<usize> {
    if typ == TYPE_IPV6 {
        if body.len() < IPV6_META_LEN || body[16] & 0xf0 != 0 {
            return None;
        }
        let local: &[u8; 16] = local.try_into().ok()?;
        let payload_len = body.len() - IPV6_META_LEN;
        if payload_len > u16::MAX as usize {
            return None;
        }
        let len = payload_len + 40;
        let ip = out.get_mut(..len)?;
        ip[..40].fill(0);
        ip[..4].copy_from_slice(&body[16..20]);
        ip[0] |= 0x60;
        ip[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        ip[6..8].copy_from_slice(&body[20..22]);
        let (l, p) = if to_server { (8, 24) } else { (24, 8) };
        ip[l..l + 16].copy_from_slice(local);
        ip[p..p + 16].copy_from_slice(&body[..16]);
        ip[40..].copy_from_slice(&body[IPV6_META_LEN..]);
        replace_local_checksum6(ip, &[0; 16], local)?;
        return Some(len);
    }
    let local: [u8; 4] = local.try_into().ok()?;
    if typ != TYPE_DATA || body.len() < IPV4_META_LEN {
        return None;
    }
    let flags = body[6];
    let options = (flags & 15) as usize * 4;
    // Reserved flag, MF, spare bit and invalid option counts are rejected.
    if flags & 0xb0 != 0 || options > 40 || body.len() < IPV4_META_LEN + options {
        return None;
    }
    let len = body.len().checked_add(IPV4_SAVING)?;
    if len > u16::MAX as usize {
        return None;
    }
    let ip = out.get_mut(..len)?;
    ip[..20].fill(0);
    ip[0] = 0x45 + options as u8 / 4;
    ip[1] = body[7];
    ip[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&body[4..6]);
    ip[6] = flags & 0x40;
    ip[8] = body[8];
    ip[9] = body[9];
    let (local_offset, peer_offset) = if to_server { (12, 16) } else { (16, 12) };
    ip[local_offset..local_offset + 4].copy_from_slice(&local);
    ip[peer_offset..peer_offset + 4].copy_from_slice(&body[..4]);
    ip[20..].copy_from_slice(&body[IPV4_META_LEN..]);
    replace_local_checksum(ip, 20 + options, 0, u32::from_ne_bytes(local))?;
    let sum: u64 = ip[..20 + options]
        .chunks_exact(2)
        .map(|w| u16::from_ne_bytes([w[0], w[1]]) as u64)
        .sum();
    ip[10..12].copy_from_slice(&(!crate::csum::fold(sum)).to_ne_bytes());
    Some(len)
}

fn replace_local_checksum(ip: &mut [u8], ihl: usize, old: u32, new: u32) -> Option<()> {
    let proto = ip[9];
    let offset = ihl
        + match proto {
            6 => 16,
            17 => 6,
            1 => return (ip.len() >= ihl + 8).then_some(()),
            _ => return None,
        };
    let bytes = ip.get_mut(offset..offset + 2)?;
    let check = u16::from_ne_bytes([bytes[0], bytes[1]]);
    let check = if proto == 17 {
        crate::csum::udp_replace4(check, old, new)
    } else {
        crate::csum::replace4(check, old, new)
    };
    bytes.copy_from_slice(&check.to_ne_bytes());
    Some(())
}

/// Includes ICMPv6's pseudo-header; zero IPv6 UDP checksums are invalid.
fn replace_local_checksum6(ip: &mut [u8], old: &[u8; 16], new: &[u8; 16]) -> Option<()> {
    let proto = ip[6];
    let (minimum, offset) = match proto {
        6 => (60, 56),
        17 => (48, 46),
        58 => (48, 42),
        _ => return None,
    };
    if ip.len() < minimum {
        return None;
    }
    let check = u16::from_ne_bytes([ip[offset], ip[offset + 1]]);
    if proto == 17 && check == 0 {
        return None;
    }
    let mut sum = !check as u64;
    for i in (0..16).step_by(2) {
        sum += (!u16::from_ne_bytes([old[i], old[i + 1]])) as u64
            + u16::from_ne_bytes([new[i], new[i + 1]]) as u64;
    }
    let check = !crate::csum::fold(sum);
    let check = if proto == 17 && check == 0 {
        0xffff
    } else {
        check
    };
    ip[offset..offset + 2].copy_from_slice(&check.to_ne_bytes());
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: Key = Key {
        k0: 0x0123_4567_89ab_cdef,
        k1: 0xfedc_ba98_7654_3210,
    };

    fn sum(bytes: &[u8]) -> u16 {
        let total: u64 = bytes
            .chunks(2)
            .map(|w| ((w[0] as u64) << 8) | w.get(1).copied().unwrap_or(0) as u64)
            .sum();
        !crate::csum::fold(total)
    }
    fn check_l4(ip: &[u8]) -> u16 {
        let ihl = (ip[0] & 15) as usize * 4;
        if ip[9] == 1 {
            return sum(&ip[ihl..]);
        }
        let mut pseudo = [0u8; 128];
        pseudo[..8].copy_from_slice(&ip[12..20]);
        pseudo[9] = ip[9];
        pseudo[10..12].copy_from_slice(&((ip.len() - ihl) as u16).to_be_bytes());
        pseudo[12..12 + ip.len() - ihl].copy_from_slice(&ip[ihl..]);
        sum(&pseudo[..12 + ip.len() - ihl])
    }
    fn fixture(
        out: &mut [u8],
        local: [u8; 4],
        proto: u8,
        options: usize,
        to_server: bool,
        df: u8,
    ) -> usize {
        let ihl = 20 + options;
        let n = ihl + if proto == 6 { 20 } else { 8 } + 5;
        let ip = &mut out[..n];
        ip.fill(0);
        ip[0] = 0x45 + options as u8 / 4;
        ip[1] = 0xab; // DSCP and CE survive both directions.
        ip[2..4].copy_from_slice(&(n as u16).to_be_bytes());
        ip[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        ip[6] = df;
        ip[8] = 61;
        ip[9] = proto;
        let (l, r) = if to_server { (12, 16) } else { (16, 12) };
        ip[l..l + 4].copy_from_slice(&local);
        ip[r..r + 4].copy_from_slice(&[203, 0, 113, 9]);
        ip[20..ihl].fill(1);
        ip[ihl..ihl + 4].copy_from_slice(&[0x12, 0x34, 0x01, 0xbb]);
        let check = match proto {
            6 => {
                ip[ihl + 12] = 0x50;
                ihl + 16
            }
            17 => {
                ip[ihl + 4..ihl + 6].copy_from_slice(&13u16.to_be_bytes());
                ihl + 6
            }
            _ => {
                ip[ihl] = if to_server { 8 } else { 0 };
                ip[ihl + 1] = 0;
                ip[ihl + 2..ihl + 4].fill(0);
                ihl + 2
            }
        };
        ip[n - 5..].copy_from_slice(&[2, 3, 4, 5, 6]);
        let c = check_l4(ip);
        ip[check..check + 2].copy_from_slice(&if c == 0 { 0xffff } else { c }.to_be_bytes());
        let c = sum(&ip[..ihl]);
        ip[10..12].copy_from_slice(&c.to_be_bytes());
        n
    }
    #[test]
    fn compact_ipv4_preserves_fields_checksums_options_and_hides_local_address() {
        for to_server in [false, true] {
            for proto in [1, 6, 17] {
                for options in [0, 4, 40] {
                    for df in [0, 0x40] {
                        let mut original = [0; 128];
                        let local = [172, 19, 8, 23];
                        let n = fixture(&mut original, local, proto, options, to_server, df);
                        let mut packet = [0; 160];
                        packet[HDR_LEN..HDR_LEN + n].copy_from_slice(&original[..n]);
                        let len =
                            seal_data(&KEY, -42, &mut packet[..HDR_LEN + n], to_server).unwrap();
                        assert_eq!(len, n - 1); // 9-byte envelope minus 10 omitted bytes.
                        let mut different = [0; 160];
                        fixture(
                            &mut different[HDR_LEN..],
                            [10, 99, 1, 2],
                            proto,
                            options,
                            to_server,
                            df,
                        );
                        let other_len =
                            seal_data(&KEY, -42, &mut different[..HDR_LEN + n], to_server).unwrap();
                        assert_eq!(
                            &packet[..len],
                            &different[..other_len],
                            "wire must not depend on local address"
                        );
                        let opened = open(&KEY, &mut packet[..len]).unwrap();
                        assert_eq!(opened.typ, TYPE_DATA);
                        let mut decoded = [0; 128];
                        let count = unpack(
                            opened.typ,
                            &packet[HDR_LEN..len],
                            &mut decoded,
                            &local,
                            to_server,
                        )
                        .unwrap();
                        assert_eq!(&decoded[..count], &original[..n]);
                        unpack(
                            opened.typ,
                            &packet[HDR_LEN..len],
                            &mut decoded,
                            &[0; 4],
                            to_server,
                        )
                        .unwrap();
                        assert_eq!(check_l4(&decoded[..n]), 0);
                        assert_eq!(sum(&decoded[..20 + options]), 0);
                    }
                }
            }
        }
    }
    #[test]
    fn compact_rejects_truncation_fragments_and_invalid_options() {
        let mut out = [0; 128];
        for n in 0..IPV4_META_LEN {
            assert!(unpack(TYPE_DATA, &[0; 10][..n], &mut out, &[0; 4], true).is_none());
        }
        for flag in [0x80, 0x20, 0x10, 11, 15] {
            let mut body = [0; 64];
            body[6] = flag;
            body[9] = 17;
            assert!(unpack(TYPE_DATA, &body, &mut out, &[0; 4], true).is_none());
        }
        let mut data = [0; 160];
        let n = fixture(&mut data[HDR_LEN..], [10, 1, 1, 1], 17, 0, true, 0);
        data[HDR_LEN + 7] = 1;
        assert!(seal_data(&KEY, 1, &mut data[..HDR_LEN + n], true).is_none());
    }
    #[test]
    fn compact_preserves_absent_udp_checksum() {
        let mut data = [0; 160];
        let n = fixture(&mut data[HDR_LEN..], [10, 1, 1, 1], 17, 0, true, 0);
        data[HDR_LEN + 26..HDR_LEN + 28].fill(0);
        let len = seal_data(&KEY, 1, &mut data[..HDR_LEN + n], true).unwrap();
        open(&KEY, &mut data[..len]).unwrap();
        let mut out = [0; 128];
        unpack(
            TYPE_DATA,
            &data[HDR_LEN..len],
            &mut out,
            &[192, 0, 2, 1],
            true,
        )
        .unwrap();
        assert_eq!(&out[26..28], &[0, 0]);
    }

    fn check_l4_6(ip: &[u8]) -> u16 {
        let mut pseudo = [0u8; 256];
        pseudo[..32].copy_from_slice(&ip[8..40]);
        pseudo[32..36].copy_from_slice(&((ip.len() - 40) as u32).to_be_bytes());
        pseudo[39] = ip[6];
        pseudo[40..ip.len()].copy_from_slice(&ip[40..]);
        sum(&pseudo[..ip.len()])
    }
    fn fixture6(out: &mut [u8], local: [u8; 16], proto: u8, to_server: bool, flow: u32) -> usize {
        let n = 40 + if proto == 6 { 20 } else { 8 } + 5;
        let ip = &mut out[..n];
        ip.fill(0);
        ip[..4].copy_from_slice(&(0x60000000 | flow).to_be_bytes());
        ip[4..6].copy_from_slice(&((n - 40) as u16).to_be_bytes());
        ip[6] = proto;
        ip[7] = 61;
        let (l, p) = if to_server { (8, 24) } else { (24, 8) };
        ip[l..l + 16].copy_from_slice(&local);
        ip[p..p + 16].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 9]);
        ip[40..44].copy_from_slice(&[0x12, 0x34, 0x01, 0xbb]);
        let check = match proto {
            6 => {
                ip[52] = 0x50;
                56
            }
            17 => {
                ip[44..46].copy_from_slice(&13u16.to_be_bytes());
                46
            }
            _ => {
                ip[40] = if to_server { 128 } else { 129 };
                ip[41] = 0;
                ip[42..44].fill(0);
                42
            }
        };
        ip[n - 5..].copy_from_slice(&[2, 3, 4, 5, 6]);
        let c = check_l4_6(ip);
        ip[check..check + 2]
            .copy_from_slice(&if proto == 17 && c == 0 { 0xffff } else { c }.to_be_bytes());
        n
    }
    #[test]
    fn compact_ipv6_preserves_fields_and_checksums_without_local_address() {
        let local = [
            0xfd, 0x77, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0x12, 0x34, 0x56, 0x78,
        ];
        let other = [
            0xfd, 0x88, 0, 9, 0, 8, 0, 7, 0, 6, 0, 5, 0x87, 0x65, 0x43, 0x21,
        ];
        for to_server in [false, true] {
            for proto in [6, 17, 58] {
                for flow in [0, 0x0a5abcde, 0x0fffffff] {
                    let mut original = [0; 128];
                    let n = fixture6(&mut original, local, proto, to_server, flow);
                    let mut packet = [0; 160];
                    packet[HDR_LEN..HDR_LEN + n].copy_from_slice(&original[..n]);
                    let len = seal_data(&KEY, -42, &mut packet[..HDR_LEN + n], to_server).unwrap();
                    assert_eq!(len, n + HDR_LEN - IPV6_SAVING);
                    let mut different = [0; 160];
                    fixture6(&mut different[HDR_LEN..], other, proto, to_server, flow);
                    let other_len =
                        seal_data(&KEY, -42, &mut different[..HDR_LEN + n], to_server).unwrap();
                    assert_eq!(&packet[..len], &different[..other_len]);
                    let opened = open(&KEY, &mut packet[..len]).unwrap();
                    assert_eq!(opened.typ, TYPE_IPV6);
                    assert_eq!(&packet[HDR_LEN + 16..HDR_LEN + 20], &flow.to_be_bytes());
                    let mut decoded = [0; 128];
                    let count = unpack(
                        TYPE_IPV6,
                        &packet[HDR_LEN..len],
                        &mut decoded,
                        &local,
                        to_server,
                    )
                    .unwrap();
                    assert_eq!(&decoded[..count], &original[..n]);
                    unpack(
                        TYPE_IPV6,
                        &packet[HDR_LEN..len],
                        &mut decoded,
                        &[0; 16],
                        to_server,
                    )
                    .unwrap();
                    assert_eq!(check_l4_6(&decoded[..n]), 0);
                }
            }
        }
    }
    #[test]
    fn compact_ipv6_rejects_invalid_lengths_extensions_and_zero_udp() {
        let mut packet = [0; 160];
        let n = fixture6(&mut packet[HDR_LEN..], [0xfd; 16], 17, true, 0);
        let original = packet;
        for proto in [0, 43, 44, 50, 51, 60, 59, 1] {
            packet = original;
            packet[HDR_LEN + 6] = proto;
            assert!(seal_data(&KEY, 1, &mut packet[..HDR_LEN + n], true).is_none());
        }
        packet = original;
        packet[HDR_LEN + 46..HDR_LEN + 48].fill(0);
        assert!(seal_data(&KEY, 1, &mut packet[..HDR_LEN + n], true).is_none());
        packet = original;
        packet[HDR_LEN + 5] ^= 1;
        assert!(seal_data(&KEY, 1, &mut packet[..HDR_LEN + n], true).is_none());
        packet = original;
        let len = seal_data(&KEY, 1, &mut packet[..HDR_LEN + n], true).unwrap();
        open(&KEY, &mut packet[..len]).unwrap();
        let body = &packet[HDR_LEN..len];
        let mut out = [0; 128];
        for count in 0..IPV6_META_LEN + 8 {
            assert!(unpack(TYPE_IPV6, &body[..count], &mut out, &[0; 16], true).is_none());
        }
        assert!(unpack(TYPE_IPV6, body, &mut out[..n - 1], &[0; 16], true).is_none());
        assert!(unpack(TYPE_IPV6, body, &mut out, &[0; 4], true).is_none());
        for proto in [0, 43, 44, 50, 51, 60, 59, 1] {
            let mut bad = packet;
            bad[HDR_LEN + 20] = proto;
            assert!(unpack(TYPE_IPV6, &bad[HDR_LEN..len], &mut out, &[0; 16], true).is_none());
        }
        let mut bad = packet;
        bad[HDR_LEN + 16] |= 0x60;
        assert!(unpack(TYPE_IPV6, &bad[HDR_LEN..len], &mut out, &[0; 16], true).is_none());
        let mut bad = packet;
        bad[HDR_LEN + IPV6_META_LEN + 6..HDR_LEN + IPV6_META_LEN + 8].fill(0);
        assert!(unpack(TYPE_IPV6, &bad[HDR_LEN..len], &mut out, &[0; 16], true).is_none());
    }
    #[test]
    fn compact_ipv6_udp_computed_zero_is_encoded_as_ffff() {
        let local = [0xfd, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7];
        let mut data = [0; 160];
        let n = fixture6(&mut data[HDR_LEN..], local, 17, true, 0);
        let ip = &mut data[HDR_LEN..HDR_LEN + n];
        ip[8..24].fill(0);
        ip[46..48].fill(0);
        // The payload starts on a 16-bit boundary; choose its first word so the
        // complete normalized pseudo-header sum folds to 0xffff.
        ip[48..50].fill(0);
        let patch = check_l4_6(ip);
        ip[48..50].copy_from_slice(&patch.to_be_bytes());
        assert_eq!(check_l4_6(ip), 0);
        ip[8..24].copy_from_slice(&local);
        let check = check_l4_6(ip);
        ip[46..48].copy_from_slice(&check.to_be_bytes());
        let len = seal_data(&KEY, 1, &mut data[..HDR_LEN + n], true).unwrap();
        open(&KEY, &mut data[..len]).unwrap();
        assert_eq!(
            &data[HDR_LEN + IPV6_META_LEN + 6..HDR_LEN + IPV6_META_LEN + 8],
            &[0xff, 0xff]
        );
        let mut out = [0; 128];
        unpack(TYPE_IPV6, &data[HDR_LEN..len], &mut out, &local, true).unwrap();
        assert_eq!(check_l4_6(&out[..n]), 0);
    }

    #[test]
    fn word_xor_matches_original_wire_at_every_length_and_alignment() {
        // A roundtrip alone could hide a change made to both seal and open.
        // Compare against the original byte implementation, including tails.
        for offset in 0..8 {
            for len in 0..=MAX_KS_WORDS as usize * 8 {
                let mut actual = [0xa5; MAX_KS_WORDS as usize * 8 + 16];
                let mut expected = actual;
                let seed = ks_seed(&KEY);
                for (i, b) in expected[offset..offset + len].iter_mut().enumerate() {
                    *b ^= (ks_word(seed, (i / 8) as u32) >> ((i % 8) * 8)) as u8;
                }
                xor_region(&KEY, &mut actual[offset..offset + len]);
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
            seal(&KEY, TYPE_DATA, 0x0102, pkt);
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
        seal(&KEY, TYPE_KEEPALIVE, 7, &mut pkt);
        let other = Key { k0: 1, k1: 2 };
        // Header validation is only a format check, not authentication.
        assert!(open(&other, &mut pkt).is_none());
    }

    #[test]
    fn public_id_and_exact_layout() {
        for id in [i64::MIN, -1, 0, 0x1234_5678_9abc_def0, i64::MAX] {
            let mut pkt = [0; HDR_LEN + 1];
            pkt[HDR_LEN] = 0x45;
            seal(&KEY, TYPE_DATA, id, &mut pkt);
            assert_eq!(&pkt[..8], &id.to_be_bytes());
            assert_eq!(user_id(&pkt), Some(id));
            let stream = ks_word(ks_seed(&KEY), 0).to_le_bytes();
            for (i, byte) in [0, 0x45].into_iter().enumerate() {
                assert_eq!(pkt[8 + i], byte ^ stream[i]);
            }
            assert_eq!(open(&KEY, &mut pkt).unwrap().user, id);
            assert_eq!(pkt[HDR_LEN], 0x45);
        }
    }

    #[test]
    fn rejects_truncation_and_invalid_control() {
        for len in 0..HDR_LEN {
            assert!(open(&KEY, &mut [0; HDR_LEN][..len]).is_none());
        }
        for typ in 3..=255 {
            let mut pkt = [0; HDR_LEN];
            seal(&KEY, typ, 7, &mut pkt);
            assert!(open(&KEY, &mut pkt).is_none());
        }
    }
}
