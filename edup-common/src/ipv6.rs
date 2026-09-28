/// Global unicast or ULA; exclude scoped, mapped, multicast and special addresses.
pub fn unicast(ip: [u8; 16]) -> bool {
    ip[0] & 0xe0 == 0x20 || ip[0] & 0xfe == 0xfc
}
