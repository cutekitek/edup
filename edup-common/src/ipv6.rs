//! IPv6 tunnel addresses use a /112 network and the 16-bit user ID.

#[inline(always)]
pub fn address(mut network: [u8; 16], user: u16) -> [u8; 16] {
    let id = user.to_be_bytes();
    network[14] = id[0];
    network[15] = id[1];
    network
}

/// Global unicast or ULA; exclude scoped, mapped, multicast and special addresses.
pub fn unicast(ip: [u8; 16]) -> bool {
    ip[0] & 0xe0 == 0x20 || ip[0] & 0xfe == 0xfc
}

#[cfg(feature = "std")]
pub fn network(input: &str) -> Option<[u8; 16]> {
    let (ip, prefix) = input.split_once('/')?;
    let ip = ip.parse::<std::net::Ipv6Addr>().ok()?.octets();
    (prefix == "112" && unicast(ip) && ip[14] == 0 && ip[15] == 0).then_some(ip)
}
