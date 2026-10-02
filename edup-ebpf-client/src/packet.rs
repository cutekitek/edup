//! Bounds-checked access shared by the XDP and TC programs.
//! All packet pointers are short-lived: reload them after adjusting the packet.
use aya_ebpf::programs::{TcContext, XdpContext};
use edup_common::{
    csum,
    maps::{client_stat as stat, *},
};

pub const ETH: usize = 14;

pub trait Packet {
    fn start(&self) -> usize;
    /// Read volatile, so LLVM keeps the local bounds checks the verifier needs.
    fn end(&self) -> usize;
}
impl Packet for XdpContext {
    #[inline(always)]
    fn start(&self) -> usize {
        self.data()
    }
    #[inline(always)]
    fn end(&self) -> usize {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*self.ctx).data_end)) as usize }
    }
}
impl Packet for TcContext {
    #[inline(always)]
    fn start(&self) -> usize {
        self.data()
    }
    #[inline(always)]
    fn end(&self) -> usize {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*self.skb.skb).data_end)) as usize }
    }
}

#[inline(always)]
pub fn read<T: Copy, C: Packet>(ctx: &C, offset: usize) -> Result<T, u32> {
    let ptr = ctx.start() + offset;
    if offset > 2048 || core::hint::black_box(ptr + core::mem::size_of::<T>()) > ctx.end() {
        return Err(stat::DROP_BAD);
    }
    // Ethernet leaves IPv4 and transport headers unaligned.
    Ok(unsafe { core::ptr::read_unaligned(ptr as *const T) })
}

#[inline(always)]
pub fn write<T: Copy, C: Packet>(ctx: &C, offset: usize, value: T) -> Result<(), u32> {
    let ptr = ctx.start() + offset;
    if offset > 2048 || core::hint::black_box(ptr + core::mem::size_of::<T>()) > ctx.end() {
        return Err(stat::DROP_BAD);
    }
    unsafe { core::ptr::write_unaligned(ptr as *mut T, value) };
    Ok(())
}

#[derive(Clone, Copy)]
pub struct Ip {
    pub offset: usize,
    pub header_len: usize,
    pub len: usize,
    pub proto: u8,
    pub frag: u16,
}

#[inline(always)]
pub fn ipv4<C: Packet>(ctx: &C, offset: usize) -> Result<Ip, u32> {
    let version = read::<u8, C>(ctx, offset)?;
    let header_len = ((version & 15) as usize) * 4;
    // Linux 6.8 loses scalar bounds after BPF_END; keep an explicit mask.
    let len =
        core::hint::black_box(u16::from_be(read::<u16, C>(ctx, offset + 2)?) as usize) & 0xffff;
    if version >> 4 != 4
        || header_len < 20
        || len < header_len
        || ctx.start() + offset + len > ctx.end()
    {
        return Err(stat::DROP_BAD);
    }
    Ok(Ip {
        offset,
        header_len,
        len,
        proto: read(ctx, offset + 9)?,
        frag: u16::from_be(read::<u16, C>(ctx, offset + 6)?),
    })
}

#[inline(always)]
pub fn ipv6<C: Packet>(ctx: &C, offset: usize) -> Result<Ip, u32> {
    let len = (core::hint::black_box(u16::from_be(read::<u16, C>(ctx, offset + 4)?) as usize)
        & 0xffff)
        + 40;
    if read::<u8, C>(ctx, offset)? >> 4 != 6 || len == 40 || ctx.start() + offset + len > ctx.end()
    {
        return Err(stat::DROP_BAD);
    }
    Ok(Ip {
        offset,
        header_len: 40,
        len,
        proto: read(ctx, offset + 6)?,
        frag: 0,
    })
}

#[derive(Clone, Copy)]
pub struct Transport {
    pub offset: usize,
    pub check_offset: usize,
    /// TCP flags; zero for other protocols.
    pub flags: u8,
}

/// The protocols the tunnel carries: TCP, UDP and ICMP/ICMPv6 echo
/// (requests outbound, replies inbound). Fragments are unsupported.
#[inline(always)]
pub fn transport<C: Packet>(ctx: &C, ip: &Ip, v6: bool, outbound: bool) -> Result<Transport, u32> {
    if ip.frag & 0x3fff != 0 {
        return Err(stat::DROP_UNSUPPORTED);
    }
    let offset = ip.offset + ip.header_len;
    let len = ip.len - ip.header_len;
    let (check_offset, flags) = match ip.proto {
        IPPROTO_TCP => {
            if len < 20 {
                return Err(stat::DROP_BAD);
            }
            let hlen = ((read::<u8, C>(ctx, offset + 12)? >> 4) as usize) * 4;
            if hlen < 20 || hlen > len {
                return Err(stat::DROP_BAD);
            }
            (offset + 16, read(ctx, offset + 13)?)
        }
        IPPROTO_UDP => {
            if len < 8
                || u16::from_be(read::<u16, C>(ctx, offset + 4)?) as usize != len
                || (v6 && read::<u16, C>(ctx, offset + 6)? == 0)
            {
                return Err(stat::DROP_BAD);
            }
            (offset + 6, 0)
        }
        IPPROTO_ICMP if !v6 => {
            if len < 8
                || read::<u8, C>(ctx, offset)? != if outbound { 8 } else { 0 }
                || read::<u8, C>(ctx, offset + 1)? != 0
            {
                return Err(stat::DROP_UNSUPPORTED);
            }
            (offset + 2, 0)
        }
        IPPROTO_ICMPV6 if v6 => {
            if len < 8
                || read::<u8, C>(ctx, offset)? != if outbound { 128 } else { 129 }
                || read::<u8, C>(ctx, offset + 1)? != 0
            {
                return Err(stat::DROP_UNSUPPORTED);
            }
            (offset + 2, 0)
        }
        _ => return Err(stat::DROP_UNSUPPORTED),
    };
    Ok(Transport {
        offset,
        check_offset,
        flags,
    })
}

/// Replace the local address in the transport checksum: the wire format
/// omits it, as if it were zero. ICMP has no pseudo header.
#[inline(never)]
pub fn replace_local4<C: Packet>(
    ctx: &C,
    proto: u8,
    check_offset: usize,
    old: u32,
    new: u32,
) -> Result<(), u32> {
    let check = read::<u16, C>(ctx, check_offset)?;
    let check = match proto {
        IPPROTO_UDP => csum::udp_replace4(check, old, new),
        IPPROTO_TCP => csum::replace4(check, old, new),
        _ => return Ok(()),
    };
    write(ctx, check_offset, check)
}

/// IPv6 variant: TCP, UDP and ICMPv6 all include the pseudo header, and a
/// computed zero UDP checksum is sent as 0xffff.
#[inline(never)]
pub fn replace_local6<C: Packet>(
    ctx: &C,
    udp: bool,
    check_offset: usize,
    old: &[u8; 16],
    new: &[u8; 16],
) -> Result<(), u32> {
    let check = read::<u16, C>(ctx, check_offset)?;
    let mut sum = !check as u64;
    let mut i = 0usize;
    while i < 8 {
        // i < 8 keeps both two-byte reads inside the 16-byte addresses.
        unsafe {
            sum += !core::ptr::read_unaligned(old.as_ptr().add(i * 2).cast::<u16>()) as u64
                + core::ptr::read_unaligned(new.as_ptr().add(i * 2).cast::<u16>()) as u64;
        }
        i = core::hint::black_box(i + 1);
    }
    let mut check = !csum::fold(sum);
    if udp && check == 0 {
        check = 0xffff;
    }
    write(ctx, check_offset, check)
}

/// Lower the MSS option of a SYN or SYN-ACK to `ceiling`, so segments of
/// either side fit the tunnel. Malformed options are left alone.
#[inline(never)]
pub fn clamp_mss<C: Packet>(ctx: &C, l4: usize, ceiling: u16) -> Result<(), u32> {
    let hlen = ((read::<u8, C>(ctx, l4 + 12)? >> 4) as usize) * 4;
    let mut i = 20usize;
    let mut step = 0;
    while step < 40 {
        if i + 4 > hlen {
            break;
        }
        let kind = read::<u8, C>(ctx, l4 + i)?;
        if kind == 0 {
            break;
        }
        if kind == 1 {
            i += 1;
            step = core::hint::black_box(step + 1);
            continue;
        }
        let len = read::<u8, C>(ctx, l4 + i + 1)? as usize;
        if len < 2 {
            break;
        }
        if kind == 2 {
            let raw = read::<u16, C>(ctx, l4 + i + 2)?;
            if len == 4 && u16::from_be(raw) > ceiling {
                let mut old = raw;
                let mut new = ceiling.to_be();
                // Options need not be aligned to the checksum's 16-bit words.
                if i % 2 == 1 {
                    old = old.swap_bytes();
                    new = new.swap_bytes();
                }
                let check = read::<u16, C>(ctx, l4 + 16)?;
                write(ctx, l4 + 16, csum::replace2(check, old, new))?;
                write(ctx, l4 + i + 2, ceiling.to_be())?;
            }
            break;
        }
        i += len;
        step = core::hint::black_box(step + 1);
    }
    Ok(())
}
