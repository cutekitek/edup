#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![allow(internal_features)]

mod nat;
mod packet;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_xdp_adjust_head, bpf_xdp_adjust_tail},
    macros::{map, xdp},
    maps::{Array, LruHashMap, PerCpuArray},
    programs::XdpContext,
};
use edup_common::{
    csum,
    maps::*,
    wire::{self, Key},
};
use packet::*;

#[map]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);
#[map]
static USERS: Array<User> = Array::with_max_entries(MAX_USERS, 0);
#[map]
static NAT_OUT: LruHashMap<NatOutKey, NatOutVal> = LruHashMap::with_max_entries(NAT_ENTRIES, 0);
#[map]
static NAT_IN: LruHashMap<NatInKey, NatInVal> = LruHashMap::with_max_entries(NAT_ENTRIES, 0);
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(stat::COUNT, 0);

#[inline(always)]
fn count(index: u32) {
    if let Some(ptr) = STATS.get_ptr_mut(index) {
        unsafe { *ptr = (*ptr).wrapping_add(1) };
    }
}

#[inline(always)]
fn pass() -> Result<u32, u32> {
    count(stat::PASS);
    Ok(xdp_action::XDP_PASS)
}

#[xdp]
pub fn edup(ctx: XdpContext) -> u32 {
    match process(&ctx) {
        Ok(action) => {
            // XDP_TX bypasses the stack's Ethernet padding. In particular a
            // bare IPv4 TCP ACK is only 54 bytes after decapsulation.
            if action == xdp_action::XDP_TX {
                let size = ctx.data_end() - ctx.data();
                if size < 60 && unsafe { bpf_xdp_adjust_tail(ctx.ctx, (60 - size) as i32) } != 0 {
                    count(stat::DROP_ADJUST);
                    return xdp_action::XDP_DROP;
                }
            }
            action
        }
        Err(reason) => {
            count(reason);
            xdp_action::XDP_DROP
        }
    }
}

#[inline(always)]
fn process(ctx: &XdpContext) -> Result<u32, u32> {
    if ctx.data() + ETH + 20 > ctx.data_end() {
        return pass();
    }
    if read::<u16>(ctx, 12)? != 0x0800u16.to_be() {
        return pass();
    }
    let Some(cfg) = CONFIG.get(0) else {
        return pass();
    };
    if cfg.port_be == 0 {
        return pass();
    }
    let dst = read::<u32>(ctx, ETH + 16)?;
    if dst != cfg.server_ip_be && dst != cfg.nat_ip_be {
        return pass();
    }
    // Invalid host traffic is the host stack's concern; do not modify it.
    let Ok(ip) = ipv4(ctx, ETH) else {
        return pass();
    };
    if ip.frag & 0x1fff != 0 {
        return pass();
    }
    let l4 = ETH + ip.header_len;
    if ip.proto == IPPROTO_UDP
        && ip.len >= ip.header_len + 8
        && dst == cfg.server_ip_be
        && read::<u16>(ctx, l4 + 2)? == cfg.port_be
    {
        count(stat::RX_TUNNEL);
        return from_client(ctx, cfg, &ip);
    }
    if dst != cfg.nat_ip_be {
        return pass();
    }
    from_internet(ctx, cfg, &ip)
}

// Keep inbound NAT temporaries off the entrypoint's frame: that frame also
// remains live while the deeper outbound NAT call chain runs (512-byte limit).
#[inline(never)]
fn from_internet(ctx: &XdpContext, cfg: &Config, ip: &Ip) -> Result<u32, u32> {
    let Ok(transport) = transport(ctx, ip, false) else {
        return pass();
    };
    let key = NatInKey {
        pub_port_be: transport.port,
        proto: ip.proto,
        _pad: 0,
    };
    let now = unsafe { bpf_ktime_get_ns() };
    let Some(mapping) = nat::inbound(&key, transport.flags, now) else {
        return pass();
    };
    count(stat::RX_INTERNET);
    to_client(ctx, cfg, ip, &transport, &mapping)
}

// Inlining lets the compiler reuse scratch slots instead of adding a live
// nested frame to the inbound path on kernels with the 512-byte stack limit.
#[inline(always)]
fn xor(ctx: &XdpContext, offset: usize, len: usize, seed: u64) -> Result<(), u32> {
    if len > wire::MAX_KS_WORDS as usize * 8 {
        return Err(stat::DROP_TOO_BIG);
    }
    for word in 0..wire::MAX_KS_WORDS {
        let base = word as usize * 8;
        if base + 8 > len {
            break;
        }
        let key = wire::ks_word(seed, word);
        let pos = offset + base;
        write(ctx, pos, read::<u64>(ctx, pos)? ^ key.to_le())?;
    }
    let full = len / 8;
    let key = wire::ks_word(seed, full as u32);
    for byte in 0..7 {
        if byte >= len % 8 {
            break;
        }
        let pos = offset + full * 8 + byte;
        write(ctx, pos, read::<u8>(ctx, pos)? ^ (key >> (byte * 8)) as u8)?;
    }
    Ok(())
}

#[inline(always)]
fn trim(ctx: &XdpContext, len: usize) -> Result<(), u32> {
    let current = ctx.data_end() - ctx.data();
    if len > current {
        return Err(stat::DROP_BAD_HDR);
    }
    if len < current && unsafe { bpf_xdp_adjust_tail(ctx.ctx, len as i32 - current as i32) } != 0 {
        return Err(stat::DROP_ADJUST);
    }
    Ok(())
}

#[inline(always)]
fn endpoint(user: u16, ip: u32, port: u16, now: u64) {
    if let Some(ptr) = USERS.get_ptr_mut(user as u32) {
        unsafe {
            // Aligned 64-bit writes publish address + port together on BPF64.
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*ptr).endpoint),
                User::pack_endpoint(ip, port),
            );
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).last_seen_ns), now);
        }
    }
}

#[inline(never)]
fn from_client(ctx: &XdpContext, cfg: &Config, outer: &Ip) -> Result<u32, u32> {
    // The protocol has fixed overhead: outer IPv4 options aren't supported.
    if outer.header_len != 20 || outer.frag & 0x3fff != 0 || outer.len < wire::OVERHEAD_V4 {
        return Err(stat::DROP_BAD_HDR);
    }
    if outer.len > cfg.max_frame as usize {
        return Err(stat::DROP_TOO_BIG);
    }
    let udp_len = u16::from_be(read::<u16>(ctx, ETH + 24)?) as usize;
    if udp_len != outer.len - 20 {
        return Err(stat::DROP_BAD_HDR);
    }
    let nonce = u32::from_le(read(ctx, ETH + 28)?);
    let seed = wire::ks_seed(
        &Key {
            k0: cfg.key0,
            k1: cfg.key1,
        },
        nonce,
    );
    let hdr = u32::from_le(read::<u32>(ctx, ETH + 32)?) ^ wire::ks_word(seed, 0) as u32;
    let (typ, flags, user) = wire::parse_hdr_word(hdr).ok_or(stat::DROP_BAD_HDR)?;
    if flags != 0 || (typ != wire::TYPE_DATA && typ != wire::TYPE_KEEPALIVE) {
        return Err(stat::DROP_BAD_HDR);
    }
    let u = USERS.get(user as u32).ok_or(stat::DROP_UNKNOWN_USER)?;
    if u.enabled == 0 {
        return Err(stat::DROP_UNKNOWN_USER);
    }
    let port = read::<u16>(ctx, ETH + 20)?;
    if port == 0 {
        return Err(stat::DROP_BAD_HDR);
    }
    let now = unsafe { bpf_ktime_get_ns() };
    let mac = swapped_mac(ctx)?;
    if typ == wire::TYPE_KEEPALIVE {
        if outer.len != wire::OVERHEAD_V4 {
            return Err(stat::DROP_BAD_HDR);
        }
        endpoint(user, outer.src, port, now);
        trim(ctx, ETH + outer.len)?;
        write_outer(
            ctx,
            outer.len,
            cfg.server_ip_be,
            outer.src,
            cfg.port_be,
            port,
        )?;
        write(ctx, 0, mac)?;
        count(stat::KEEPALIVE);
        return Ok(xdp_action::XDP_TX);
    }
    xor(ctx, ETH + 32, outer.len - 32, seed)?;
    let inner = ipv4(ctx, ETH + wire::OVERHEAD_V4).map_err(|_| stat::DROP_BAD_INNER)?;
    if inner.len + wire::OVERHEAD_V4 != outer.len {
        return Err(stat::DROP_BAD_INNER);
    }
    if inner.src != cfg.tun_net.wrapping_add(user as u32).to_be() {
        return Err(stat::DROP_SPOOF);
    }
    let l4 = transport(ctx, &inner, true)?;
    if inner.ttl <= 1 {
        return Err(stat::DROP_TTL);
    }
    endpoint(user, outer.src, port, now);
    let key = NatOutKey {
        inner_ip_be: inner.src,
        inner_port_be: l4.port,
        proto: inner.proto,
        _pad: 0,
    };
    let public_port = nat::outbound(&key, user, l4.flags, cfg, now);
    if public_port == 0 {
        return Err(stat::DROP_NAT_FULL);
    }
    translate(ctx, &inner, &l4, cfg.nat_ip_be, public_port, true)?;
    trim(ctx, ETH + outer.len)?;
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, wire::OVERHEAD_V4 as i32) } != 0 {
        return Err(stat::DROP_ADJUST);
    }
    write(ctx, 0, mac)?;
    write(ctx, 12, 0x0800u16.to_be())?;
    count(stat::TX_INTERNET);
    Ok(xdp_action::XDP_TX)
}

#[inline(never)]
fn to_client(
    ctx: &XdpContext,
    cfg: &Config,
    ip: &Ip,
    l4: &Transport,
    mapping: &NatInVal,
) -> Result<u32, u32> {
    let u = USERS
        .get(mapping.user as u32)
        .ok_or(stat::DROP_UNKNOWN_USER)?;
    if u.enabled == 0 {
        return Err(stat::DROP_UNKNOWN_USER);
    }
    let ep = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(u.endpoint)) };
    if ep == 0 {
        return Err(stat::DROP_NO_ENDPOINT);
    }
    let len = ip.len + wire::OVERHEAD_V4;
    if len > cfg.max_frame as usize || ip.len + 4 > wire::MAX_KS_WORDS as usize * 8 {
        return Err(stat::DROP_TOO_BIG);
    }
    let mac = swapped_mac(ctx)?;
    translate(
        ctx,
        ip,
        l4,
        mapping.inner_ip_be,
        mapping.inner_port_be,
        false,
    )?;
    trim(ctx, ETH + ip.len)?;
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(wire::OVERHEAD_V4 as i32)) } != 0 {
        return Err(stat::DROP_ADJUST);
    }
    write(ctx, 0, mac)?;
    write(ctx, 12, 0x0800u16.to_be())?;
    write_outer(
        ctx,
        len,
        cfg.server_ip_be,
        User::endpoint_ip_be(ep),
        cfg.port_be,
        User::endpoint_port_be(ep),
    )?;
    let nonce = unsafe { bpf_get_prandom_u32() };
    write(ctx, ETH + 28, nonce.to_le())?;
    write(
        ctx,
        ETH + 32,
        wire::hdr_word(wire::TYPE_DATA, mapping.user).to_le(),
    )?;
    xor(
        ctx,
        ETH + 32,
        ip.len + 4,
        wire::ks_seed(
            &Key {
                k0: cfg.key0,
                k1: cfg.key1,
            },
            nonce,
        ),
    )?;
    count(stat::TX_TUNNEL);
    Ok(xdp_action::XDP_TX)
}

#[inline(always)]
fn write_outer(
    ctx: &XdpContext,
    len: usize,
    src: u32,
    dst: u32,
    sport: u16,
    dport: u16,
) -> Result<(), u32> {
    let words = [
        0x0045u16.to_le(),
        (len as u16).to_be(),
        0,
        0x4000u16.to_be(),
        u16::from_ne_bytes([64, IPPROTO_UDP]),
        0,
        src as u16,
        (src >> 16) as u16,
        dst as u16,
        (dst >> 16) as u16,
    ];
    write(ctx, ETH, words)?;
    write(ctx, ETH + 10, csum::ipv4_header(&words))?;
    write(ctx, ETH + 20, sport)?;
    write(ctx, ETH + 22, dport)?;
    write(ctx, ETH + 24, ((len - 20) as u16).to_be())?;
    // An absent UDP checksum is explicitly allowed for outer IPv4.
    write(ctx, ETH + 26, 0u16)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
