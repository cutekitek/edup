//! All packet pointers are short-lived: reload them after adjust_head/tail.
use aya_ebpf::programs::XdpContext;
use edup_common::{csum, maps::*};

pub const ETH: usize = 14;

#[inline(always)]
fn data_end(ctx: &XdpContext) -> usize {
    // Prevent LLVM from removing local bounds checks based on relationships
    // (IPv4 total length vs IHL) that the kernel verifier cannot reconstruct.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*ctx.ctx).data_end)) as usize }
}

#[inline(always)]
pub fn read<T: Copy>(ctx: &XdpContext, offset: usize) -> Result<T, u32> {
    let ptr = ctx.data() + offset;
    if offset > 2048 || core::hint::black_box(ptr + core::mem::size_of::<T>()) > data_end(ctx) {
        return Err(stat::DROP_BAD_HDR);
    }
    // Ethernet leaves IPv4 and transport headers unaligned.
    Ok(unsafe { core::ptr::read_unaligned(ptr as *const T) })
}

#[inline(always)]
pub fn write<T: Copy>(ctx: &XdpContext, offset: usize, value: T) -> Result<(), u32> {
    let ptr = ctx.data() + offset;
    if offset > 2048 || core::hint::black_box(ptr + core::mem::size_of::<T>()) > data_end(ctx) {
        return Err(stat::DROP_BAD_HDR);
    }
    unsafe { core::ptr::write_unaligned(ptr as *mut T, value) };
    Ok(())
}

#[derive(Clone, Copy)]
pub struct Ip {
    pub offset: usize,
    pub header_len: usize,
    pub len: usize,
    pub src: u32,
    pub dst: u32,
    pub proto: u8,
    pub ttl: u8,
    pub frag: u16,
    pub v6: u8,
}

#[inline(always)]
pub fn ipv4(ctx: &XdpContext, offset: usize) -> Result<Ip, u32> {
    let version = read::<u8>(ctx, offset)?;
    let header_len = ((version & 15) as usize) * 4;
    // Linux 6.8 loses scalar bounds after BPF_END. Keep an explicit mask after
    // byte swapping so pointer arithmetic remains bounded on older verifiers.
    let len = core::hint::black_box(u16::from_be(read::<u16>(ctx, offset + 2)?) as usize) & 0xffff;
    if version >> 4 != 4
        || header_len < 20
        || len < header_len
        || ctx.data() + offset + len > ctx.data_end()
    {
        return Err(stat::DROP_BAD_INNER);
    }
    Ok(Ip {
        offset,
        header_len,
        len,
        src: read(ctx, offset + 12)?,
        dst: read(ctx, offset + 16)?,
        proto: read(ctx, offset + 9)?,
        ttl: read(ctx, offset + 8)?,
        frag: u16::from_be(read::<u16>(ctx, offset + 6)?),
        v6: 0,
    })
}

#[inline(always)]
pub fn ipv6(ctx: &XdpContext, offset: usize) -> Result<Ip, u32> {
    let len =
        (core::hint::black_box(u16::from_be(read::<u16>(ctx, offset + 4)?) as usize) & 0xffff) + 40;
    if read::<u8>(ctx, offset)? >> 4 != 6 || len == 40 || ctx.data() + offset + len > ctx.data_end()
    {
        return Err(stat::DROP_BAD_INNER);
    }
    Ok(Ip {
        offset,
        header_len: 40,
        len,
        src: 0,
        dst: 0,
        proto: read(ctx, offset + 6)?,
        ttl: read(ctx, offset + 7)?,
        frag: 0,
        v6: 1,
    })
}

#[derive(Clone, Copy)]
pub struct Transport {
    pub port: u16,
    pub port_offset: usize,
    pub check_offset: usize,
    pub flags: u8,
}

#[inline(always)]
pub fn transport(ctx: &XdpContext, ip: &Ip, outbound: bool) -> Result<Transport, u32> {
    if ip.frag & 0x3fff != 0 {
        return Err(stat::DROP_BAD_INNER);
    }
    let offset = ip.offset + ip.header_len;
    let len = ip.len - ip.header_len;
    let (port_offset, check_offset, flags) = match ip.proto {
        IPPROTO_TCP => {
            if len < 20 {
                return Err(stat::DROP_BAD_INNER);
            }
            let hlen = ((read::<u8>(ctx, offset + 12)? >> 4) as usize) * 4;
            if hlen < 20 || hlen > len {
                return Err(stat::DROP_BAD_INNER);
            }
            (
                offset + if outbound { 0 } else { 2 },
                offset + 16,
                read(ctx, offset + 13)?,
            )
        }
        IPPROTO_UDP => {
            if len < 8
                || u16::from_be(read::<u16>(ctx, offset + 4)?) as usize != len
                || (ip.v6 != 0 && read::<u16>(ctx, offset + 6)? == 0)
            {
                return Err(stat::DROP_BAD_INNER);
            }
            (offset + if outbound { 0 } else { 2 }, offset + 6, 0)
        }
        IPPROTO_ICMP if ip.v6 == 0 => {
            if len < 8 {
                return Err(stat::DROP_BAD_INNER);
            }
            if read::<u8>(ctx, offset)? != if outbound { 8 } else { 0 }
                || read::<u8>(ctx, offset + 1)? != 0
            {
                return Err(stat::DROP_PROTO);
            }
            (offset + 4, offset + 2, 0)
        }
        IPPROTO_ICMPV6 if ip.v6 != 0 => {
            if len < 8 {
                return Err(stat::DROP_BAD_INNER);
            }
            if read::<u8>(ctx, offset)? != if outbound { 128 } else { 129 }
                || read::<u8>(ctx, offset + 1)? != 0
            {
                return Err(stat::DROP_PROTO);
            }
            (offset + 4, offset + 2, 0)
        }
        _ => return Err(stat::DROP_PROTO),
    };
    Ok(Transport {
        port: read(ctx, port_offset)?,
        port_offset,
        check_offset,
        flags,
    })
}

#[inline(never)]
pub fn translate6(
    ctx: &XdpContext,
    ip: &Ip,
    l4: &Transport,
    address: &[u8; 16],
    port_direction: u32,
) -> Result<(), u32> {
    let port = port_direction as u16;
    let outbound = port_direction & (1 << 16) != 0;
    if ip.ttl <= 1 {
        return Err(stat::DROP_TTL);
    }
    let offset = ip.offset + if outbound { 8 } else { 24 };
    let check = read::<u16>(ctx, l4.check_offset)?;
    let mut sum = !check as u64 + !l4.port as u64 + port as u64;
    let mut i = 0usize;
    while i < 8 {
        let old = read::<u16>(ctx, offset + i * 2)?;
        // i < 8 guarantees this two-byte read is inside the 16-byte address.
        sum += !old as u64
            + unsafe { core::ptr::read_unaligned(address.as_ptr().add(i * 2).cast::<u16>()) }
                as u64;
        // Keep this bounded walk as a loop; unrolling spills all 128 address bits.
        i = core::hint::black_box(i + 1);
    }
    let mut check = !csum::fold(sum);
    if ip.proto == IPPROTO_UDP && check == 0 {
        check = 0xffff;
    }
    write(ctx, l4.check_offset, check)?;
    write(ctx, l4.port_offset, port)?;
    write(ctx, offset, *address)?;
    write(ctx, ip.offset + 7, ip.ttl - 1)
}

#[inline(always)]
pub fn translate(
    ctx: &XdpContext,
    ip: &Ip,
    l4: &Transport,
    address: u32,
    port: u16,
    outbound: bool,
) -> Result<(), u32> {
    if ip.ttl <= 1 {
        return Err(stat::DROP_TTL);
    }
    let old = if outbound { ip.src } else { ip.dst };
    let check = read::<u16>(ctx, l4.check_offset)?;
    let check = match ip.proto {
        IPPROTO_UDP => csum::udp_replace2(csum::udp_replace4(check, old, address), l4.port, port),
        IPPROTO_TCP => csum::replace2(csum::replace4(check, old, address), l4.port, port),
        _ => csum::replace2(check, l4.port, port),
    };
    write(ctx, l4.check_offset, check)?;
    write(ctx, l4.port_offset, port)?;
    let old_ttl = u16::from_ne_bytes([ip.ttl, ip.proto]);
    let new_ttl = u16::from_ne_bytes([ip.ttl - 1, ip.proto]);
    let check = csum::replace2(
        csum::replace4(read(ctx, ip.offset + 10)?, old, address),
        old_ttl,
        new_ttl,
    );
    write(ctx, ip.offset + 10, check)?;
    write(ctx, ip.offset + 8, ip.ttl - 1)?;
    write(ctx, ip.offset + if outbound { 12 } else { 16 }, address)
}

#[inline(always)]
pub fn swapped_mac(ctx: &XdpContext) -> Result<[u8; 12], u32> {
    let dst: [u8; 6] = read(ctx, 0)?;
    let src: [u8; 6] = read(ctx, 6)?;
    Ok([
        src[0], src[1], src[2], src[3], src[4], src[5], dst[0], dst[1], dst[2], dst[3], dst[4],
        dst[5],
    ])
}
