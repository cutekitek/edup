//! Validate segmented, checksum-complete IP packets before touching fields.
//! Fragmented IPv4 is not supported.
use edup_common::csum;

pub fn validate(ip: &[u8], address: [u8; 4], outbound: bool, mtu: u16) -> Option<usize> {
    if ip.len() < 20 || ip.len() > mtu as usize || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = (ip[0] & 15) as usize * 4;
    if ihl < 20 || ihl > ip.len() || be16(ip, 2) as usize != ip.len() || be16(ip, 6) & 0x3fff != 0 {
        return None;
    }
    if ip[if outbound { 12..16 } else { 16..20 }] != address {
        return None;
    }
    validate_transport(&ip[ihl..], ip[9], false, outbound)?;
    Some(ihl)
}

pub fn validate_family(
    ip: &[u8],
    address: [u8; 4],
    address6: Option<[u8; 16]>,
    outbound: bool,
    mtu: u16,
) -> Option<usize> {
    if address6.is_none() {
        return validate(ip, address, outbound, mtu);
    }
    if ip.first()? >> 4 != 6 {
        return None;
    }
    let address6 = address6?;
    if ip.len() < 40
        || ip.len() > mtu as usize
        || be16(ip, 4) as usize + 40 != ip.len()
        || ip[if outbound { 8..24 } else { 24..40 }] != address6
    {
        return None;
    }
    // Extension headers (including fragments) are deliberately unsupported.
    validate_transport(&ip[40..], ip[6], true, outbound)?;
    Some(40)
}

fn validate_transport(l4: &[u8], proto: u8, v6: bool, outbound: bool) -> Option<()> {
    match proto {
        6 => {
            if l4.len() < 20 {
                return None;
            }
            let hlen = (l4[12] >> 4) as usize * 4;
            if hlen < 20 || hlen > l4.len() {
                return None;
            }
            let mut i = 20;
            while i < hlen {
                match l4[i] {
                    0 => break,
                    1 => i += 1,
                    kind => {
                        if i + 2 > hlen {
                            return None;
                        }
                        let len = l4[i + 1] as usize;
                        if len < 2 || i + len > hlen || (kind == 2 && len != 4) {
                            return None;
                        }
                        i += len;
                    }
                }
            }
        }
        17 => {
            if l4.len() < 8 || be16(l4, 4) as usize != l4.len() || (v6 && be16(l4, 6) == 0) {
                return None;
            }
        }
        1 if !v6 => {
            if l4.len() < 8 || l4[1] != 0 || l4[0] != if outbound { 8 } else { 0 } {
                return None;
            }
        }
        58 if v6 => {
            if l4.len() < 8 || l4[1] != 0 || l4[0] != if outbound { 128 } else { 129 } {
                return None;
            }
        }
        _ => return None,
    }
    Some(())
}

/// Called after validate. Covers both SYN and SYN-ACK, without growing headers.
pub fn clamp_mss(ip: &mut [u8], ihl: usize, mtu: u16) {
    let v6 = ip[0] >> 4 == 6;
    if ip[if v6 { 6 } else { 9 }] != 6 || ip[ihl + 13] & 2 == 0 {
        return;
    }
    // RFC 6691: advertised MSS excludes the fixed IP+TCP headers. TCP handles
    // options separately when constructing segments.
    let ceiling = mtu - if v6 { 60 } else { 40 };
    let end = ihl + ((ip[ihl + 12] >> 4) as usize * 4);
    let mut i = ihl + 20;
    while i < end {
        match ip[i] {
            0 => break,
            1 => i += 1,
            kind => {
                let len = ip[i + 1] as usize;
                if kind == 2 && be16(ip, i + 2) > ceiling {
                    let mut old = u16::from_ne_bytes([ip[i + 2], ip[i + 3]]);
                    let mut new = ceiling.to_be();
                    // Options need not be aligned to the checksum's 16-bit words.
                    if !(i + 2 - ihl).is_multiple_of(2) {
                        old = old.swap_bytes();
                        new = new.swap_bytes();
                    }
                    let check = u16::from_ne_bytes([ip[ihl + 16], ip[ihl + 17]]);
                    ip[i + 2..i + 4].copy_from_slice(&ceiling.to_be_bytes());
                    ip[ihl + 16..ihl + 18]
                        .copy_from_slice(&csum::replace2(check, old, new).to_ne_bytes());
                }
                i += len;
            }
        }
    }
}
fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;
    fn checksum(b: &[u8]) -> u16 {
        let mut s: u32 = b
            .chunks(2)
            .map(|p| (p[0] as u32) << 8 | p.get(1).copied().unwrap_or(0) as u32)
            .sum();
        while s > 65535 {
            s = (s & 65535) + (s >> 16);
        }
        !(s as u16)
    }
    fn tcp_sum(ip: &[u8]) -> u16 {
        let ihl = (ip[0] & 15) as usize * 4;
        let mut p = ip[12..20].to_vec();
        p.extend([0, 6]);
        p.extend(((ip.len() - ihl) as u16).to_be_bytes());
        p.extend(&ip[ihl..]);
        checksum(&p)
    }
    fn syn(flags: u8) -> Vec<u8> {
        let mut p = vec![0; 48];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&48u16.to_be_bytes());
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 66, 0, 7]);
        p[16..20].copy_from_slice(&[1, 2, 3, 4]);
        p[32] = 0x70;
        p[33] = flags;
        p[40..48].copy_from_slice(&[1, 2, 4, 0x05, 0xb4, 1, 0, 0]);
        let c = tcp_sum(&p);
        p[36..38].copy_from_slice(&c.to_be_bytes());
        p
    }
    #[test]
    fn syn_and_syn_ack_checksum_and_odd_option_offset() {
        for flags in [2, 18] {
            let mut p = syn(flags);
            assert_eq!(tcp_sum(&p), 0);
            let ihl = validate(&p, [10, 66, 0, 7], true, 1464).unwrap();
            clamp_mss(&mut p, ihl, 1464);
            assert_eq!(be16(&p, 43), 1424);
            assert_eq!(tcp_sum(&p), 0);
        }
    }
    #[test]
    fn does_not_raise_mss_or_edit_ack() {
        let mut p = syn(16);
        let old = p.clone();
        clamp_mss(&mut p, 20, 1464);
        assert_eq!(p, old);
        let mut p = syn(2);
        clamp_mss(&mut p, 20, 1200);
        let old = p.clone();
        clamp_mss(&mut p, 20, 1464);
        assert_eq!(p, old);
    }
    #[test]
    fn rejects_malformed_options_fragments_and_wrong_address() {
        let p = syn(2);
        for len in [0, 1, 3, 40] {
            let mut b = p.clone();
            b[42] = len;
            assert!(validate(&b, [10, 66, 0, 7], true, 1464).is_none());
        }
        let mut b = p.clone();
        b[6] = 0x20;
        assert!(validate(&b, [10, 66, 0, 7], true, 1464).is_none());
        assert!(validate(&p, [10, 66, 0, 8], true, 1464).is_none());
        for n in 0..p.len() {
            assert!(validate(&p[..n], [10, 66, 0, 7], true, 1464).is_none());
        }
    }

    fn v6(proto: u8, outbound: bool, len: usize) -> Vec<u8> {
        let mut p = vec![0; 40 + len];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(len as u16).to_be_bytes());
        p[6] = proto;
        let address = "fd66::7".parse::<std::net::Ipv6Addr>().unwrap().octets();
        p[if outbound { 8..24 } else { 24..40 }].copy_from_slice(&address);
        match proto {
            6 => p[52] = 0x50,
            17 => {
                p[44..46].copy_from_slice(&(len as u16).to_be_bytes());
                p[46] = 1;
            }
            58 => p[40] = if outbound { 128 } else { 129 },
            _ => {}
        }
        p
    }
    #[test]
    fn ipv6_validation_rejects_truncation_spoofing_extensions_and_zero_udp() {
        let a = Some("fd66::7".parse::<std::net::Ipv6Addr>().unwrap().octets());
        for outbound in [false, true] {
            for proto in [6, 17, 58] {
                let p = v6(proto, outbound, 20);
                assert_eq!(validate_family(&p, [0; 4], a, outbound, 1444), Some(40));
                assert!(validate_family(&p, [0; 4], None, outbound, 1444).is_none());
                assert!(validate_family(&p, [0; 4], Some([0; 16]), outbound, 1444).is_none());
                for n in 0..p.len() {
                    assert!(validate_family(&p[..n], [0; 4], a, outbound, 1444).is_none());
                }
                let mut b = p.clone();
                b.push(0);
                assert!(validate_family(&b, [0; 4], a, outbound, 1444).is_none());
                assert!(validate_family(&p, [0; 4], a, outbound, 59).is_none());
                for next in [0, 1, 43, 44, 50, 51, 59, 60] {
                    let mut b = p.clone();
                    b[6] = next;
                    assert!(validate_family(&b, [0; 4], a, outbound, 1444).is_none());
                }
            }
        }
        let mut udp = v6(17, true, 8);
        udp[46] = 0;
        assert!(validate_family(&udp, [0; 4], a, true, 1444).is_none());
        let mut echo = v6(58, true, 8);
        echo[40] = 129;
        assert!(validate_family(&echo, [0; 4], a, true, 1444).is_none());
    }

    #[test]
    fn ipv6_mss_clamping_preserves_checksum() {
        let mut p = v6(6, true, 28);
        p[52] = 0x70;
        p[53] = 2;
        p[60..68].copy_from_slice(&[1, 2, 4, 0x05, 0xb4, 1, 0, 0]);
        let pseudo = |ip: &[u8]| {
            let mut b = ip[8..40].to_vec();
            b.extend(28u32.to_be_bytes());
            b.extend([0, 0, 0, 6]);
            b.extend(&ip[40..]);
            checksum(&b)
        };
        let c = pseudo(&p);
        p[56..58].copy_from_slice(&c.to_be_bytes());
        clamp_mss(&mut p, 40, 1444);
        assert_eq!(be16(&p, 63), 1384);
        assert_eq!(pseudo(&p), 0);
    }
}
