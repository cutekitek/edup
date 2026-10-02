//! Linux client datapath for `"mode": "xdp"`.
//!
//! - `edup_egress*` (TC egress, physical interface) looks up each destination
//!   in `ROUTES`. Bypassed packets continue unchanged; proxied packets go to the
//!   segmentation veth; unknown destinations go through the TUN device to
//!   userspace, which stores the route and re-injects the packet. Without a
//!   recent userspace heartbeat, or while a lookup stays unanswered, packets
//!   follow the standard route.
//! - `edup_encap*` (TC ingress, veth peer) receives segmented packets with
//!   complete checksums, encapsulates them and sends them to the server.
//! - `edup_ingress*` (XDP, physical interface) decapsulates server packets
//!   into ordinary packets for the local stack.
#![no_std]
#![no_main]

mod packet;

use aya_ebpf::{
    bindings::{BPF_NOEXIST, TC_ACT_SHOT, TC_ACT_UNSPEC, bpf_adj_room_mode, xdp_action},
    helpers::{
        bpf_ktime_get_ns, bpf_redirect, bpf_redirect_neigh, bpf_xdp_adjust_head,
        bpf_xdp_adjust_tail,
    },
    macros::{classifier, map, xdp},
    maps::{Array, LruHashMap, PerCpuArray},
    programs::{TcContext, XdpContext},
};
use edup_common::{
    csum,
    maps::{client_stat as stat, *},
    wire::{self, Key},
};
use packet::*;

#[map]
static CLIENT_CONFIG: Array<ClientConfig> = Array::with_max_entries(1, 0);
#[map]
static ROUTES: LruHashMap<[u8; 16], RouteEntry> = LruHashMap::with_max_entries(ROUTE_ENTRIES, 0);
/// CLOCK_MONOTONIC nanoseconds of the last userspace iteration.
#[map]
static HEARTBEAT: Array<u64> = Array::with_max_entries(1, 0);
#[map]
static CLIENT_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(stat::COUNT, 0);

#[inline(always)]
fn count(index: u32) {
    if let Some(ptr) = CLIENT_STATS.get_ptr_mut(index) {
        unsafe { *ptr = (*ptr).wrapping_add(1) };
    }
}

#[inline(always)]
const fn ether<const V6: bool>() -> u16 {
    if V6 {
        0x86ddu16.to_be()
    } else {
        0x0800u16.to_be()
    }
}

#[inline(always)]
const fn overhead<const V6: bool>() -> usize {
    if V6 {
        wire::OVERHEAD_V6
    } else {
        wire::OVERHEAD_V4
    }
}

#[classifier]
pub fn edup_egress4(ctx: TcContext) -> i32 {
    egress::<false>(&ctx).unwrap_or(TC_ACT_UNSPEC)
}

#[classifier]
pub fn edup_egress6(ctx: TcContext) -> i32 {
    egress::<true>(&ctx).unwrap_or(TC_ACT_UNSPEC)
}

#[inline(always)]
fn fallback() -> Result<i32, ()> {
    count(stat::FALLBACK);
    Ok(TC_ACT_UNSPEC)
}

#[inline(always)]
fn lookup(cfg: &ClientConfig) -> Result<i32, ()> {
    count(stat::LOOKUP);
    Ok(unsafe { bpf_redirect(cfg.tun, 0) } as i32)
}

/// Err and TC_ACT_UNSPEC leave the packet to the standard route.
#[inline(always)]
fn egress<const V6: bool>(ctx: &TcContext) -> Result<i32, ()> {
    let cfg = CLIENT_CONFIG.get(0).ok_or(())?;
    if cfg.physical == 0 || ctx.load::<u16>(12).map_err(|_| ())? != ether::<V6>() {
        return Ok(TC_ACT_UNSPEC);
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    if V6 {
        src = ctx.load(ETH + 8).map_err(|_| ())?;
        dst = ctx.load(ETH + 24).map_err(|_| ())?;
        // Multicast destinations keep their link-local handling.
        if dst[0] == 0xff {
            return Ok(TC_ACT_UNSPEC);
        }
    } else {
        src[..4].copy_from_slice(&ctx.load::<[u8; 4]>(ETH + 12).map_err(|_| ())?);
        dst[..4].copy_from_slice(&ctx.load::<[u8; 4]>(ETH + 16).map_err(|_| ())?);
        if dst[0] >= 224 {
            return Ok(TC_ACT_UNSPEC);
        }
    }
    // Other local addresses, the tunnel itself and anything else for the
    // server always take the standard route.
    if src != cfg.local || dst == cfg.server {
        return Ok(TC_ACT_UNSPEC);
    }
    let now = unsafe { bpf_ktime_get_ns() };
    let heartbeat = HEARTBEAT.get(0).copied().unwrap_or(0);
    if heartbeat == 0 || now.saturating_sub(heartbeat) >= HEARTBEAT_TIMEOUT_NS {
        return fallback();
    }
    // Userspace re-injects packets after storing their route. Never look up
    // one again, even if the LRU has already evicted that route.
    let reinjected = unsafe { (*ctx.skb.skb).mark } == cfg.mark;
    let Some(entry) = ROUTES.get_ptr_mut(&dst) else {
        if reinjected {
            return fallback();
        }
        let pending = RouteEntry {
            since_ns: now,
            action: ROUTE_PENDING,
            _pad: 0,
        };
        // Losing a race to another CPU leaves an equivalent request.
        let _ = ROUTES.insert(&dst, &pending, BPF_NOEXIST as u64);
        return lookup(cfg);
    };
    let route = unsafe { core::ptr::read_volatile(entry) };
    match route.action {
        ROUTE_BYPASS => {
            count(stat::BYPASS);
            Ok(TC_ACT_UNSPEC)
        }
        ROUTE_PROXY => {
            count(stat::PROXY);
            Ok(unsafe { bpf_redirect(cfg.segment, 0) } as i32)
        }
        _ => {
            let age = now.saturating_sub(route.since_ns);
            if reinjected || (LOOKUP_WAIT_NS..LOOKUP_RETRY_NS).contains(&age) {
                return fallback();
            }
            if age >= LOOKUP_RETRY_NS {
                // Userspace replaces the whole entry when it answers; this
                // write can only renew a request that is still pending.
                unsafe {
                    core::ptr::write_volatile(core::ptr::addr_of_mut!((*entry).since_ns), now)
                };
            }
            lookup(cfg)
        }
    }
}

#[classifier]
pub fn edup_encap4(ctx: TcContext) -> i32 {
    match encap::<false>(&ctx) {
        Ok(action) => action,
        Err(reason) => {
            count(reason);
            TC_ACT_SHOT as i32
        }
    }
}

#[classifier]
pub fn edup_encap6(ctx: TcContext) -> i32 {
    match encap::<true>(&ctx) {
        Ok(action) => action,
        Err(reason) => {
            count(reason);
            TC_ACT_SHOT as i32
        }
    }
}

/// The segmentation veth delivers single packets with complete checksums;
/// only the egress program sends traffic into it.
#[inline(always)]
fn encap<const V6: bool>(ctx: &TcContext) -> Result<i32, u32> {
    let cfg = CLIENT_CONFIG.get(0).ok_or(stat::DROP_BAD)?;
    let len = ctx.len() as usize;
    if len > ETH + cfg.mtu as usize {
        return Err(stat::DROP_TOO_BIG);
    }
    if ctx.skb.pull_data(len as u32).is_err() {
        return Err(stat::DROP_ADJUST);
    }
    if read::<u16, _>(ctx, 12)? != ether::<V6>() {
        return Err(stat::DROP_UNSUPPORTED);
    }
    let ip = if V6 { ipv6(ctx, ETH)? } else { ipv4(ctx, ETH)? };
    if ETH + ip.len != len {
        return Err(stat::DROP_BAD);
    }
    let l4 = transport(ctx, &ip, V6, true)?;
    if ip.proto == IPPROTO_TCP && l4.flags & 2 != 0 {
        clamp_mss(ctx, l4.offset, cfg.mtu - if V6 { 60 } else { 40 })?;
    }
    if V6 {
        let local = read::<[u8; 16], _>(ctx, ETH + 8)?;
        if local != cfg.local {
            return Err(stat::DROP_BAD);
        }
        replace_local6(
            ctx,
            ip.proto == IPPROTO_UDP,
            l4.check_offset,
            &local,
            &[0; 16],
        )?;
        pack_ipv6(ctx)?;
    } else {
        let local = read::<u32, _>(ctx, ETH + 12)?;
        if local.to_ne_bytes() != [cfg.local[0], cfg.local[1], cfg.local[2], cfg.local[3]] {
            return Err(stat::DROP_BAD);
        }
        replace_local4(ctx, ip.proto, l4.check_offset, local, 0)?;
        pack_ipv4(ctx, &ip)?;
    }
    let outer = ip.len + overhead::<V6>();
    let hlen = if V6 { 40 } else { 20 };
    if outer - hlen - 16 > wire::MAX_KS_WORDS as usize * 8 {
        return Err(stat::DROP_TOO_BIG);
    }
    // The new bytes follow the MAC header; the packed header now starts
    // exactly after the outer IP, UDP and wire headers.
    if ctx
        .skb
        .adjust_room(
            overhead::<V6>() as i32,
            bpf_adj_room_mode::BPF_ADJ_ROOM_MAC,
            0,
        )
        .is_err()
    {
        return Err(stat::DROP_ADJUST);
    }
    write_outer::<V6, _>(ctx, cfg, outer)?;
    write(ctx, ETH + hlen + 8, cfg.user.to_be())?;
    write(
        ctx,
        ETH + hlen + 16,
        if V6 { wire::TYPE_IPV6 } else { wire::TYPE_DATA },
    )?;
    let sum = xor::<true, _>(
        ctx,
        ETH + hlen + 16,
        outer - hlen - 16,
        wire::ks_seed(&Key {
            k0: cfg.key0,
            k1: cfg.key1,
        }),
    )?;
    finish_outer_checksum(ctx, outer, hlen, sum)?;
    ctx.set_mark(cfg.mark);
    count(stat::TX_TUNNEL);
    // The kernel routes the outer packet and resolves its next hop.
    Ok(unsafe { bpf_redirect_neigh(cfg.physical, core::ptr::null_mut(), 0, 0) } as i32)
}

/// Keep peer metadata in the last bytes of the old header. The local source
/// and the header checksum are omitted; options stay before the transport.
#[inline(never)]
fn pack_ipv4(ctx: &TcContext, ip: &Ip) -> Result<(), u32> {
    if ip.header_len > 60 || ip.frag & 0xbfff != 0 {
        return Err(stat::DROP_UNSUPPORTED);
    }
    let peer = read::<u32, _>(ctx, ETH + 16)?;
    let id = read::<u16, _>(ctx, ETH + 4)?;
    let tos = read::<u8, _>(ctx, ETH + 1)?;
    let ttl_proto = read::<u16, _>(ctx, ETH + 8)?;
    let flags = ((ip.frag >> 8) as u8 & 0x40) | (ip.header_len as u8 / 4 - 5);
    let offset = ETH + wire::IPV4_SAVING;
    write(ctx, offset, peer)?;
    write(ctx, offset + 4, id)?;
    write(ctx, offset + 6, flags)?;
    write(ctx, offset + 7, tos)?;
    write(ctx, offset + 8, ttl_proto)
}

#[inline(never)]
fn pack_ipv6(ctx: &TcContext) -> Result<(), u32> {
    let peer = read::<[u8; 16], _>(ctx, ETH + 24)?;
    let fields = read::<u32, _>(ctx, ETH)? & 0x0fffffffu32.to_be();
    let next_hop = read::<u16, _>(ctx, ETH + 6)?;
    let offset = ETH + wire::IPV6_SAVING;
    write(ctx, offset, peer)?;
    write(ctx, offset + 16, fields)?;
    write(ctx, offset + 20, next_hop)
}

#[inline(never)]
fn write_outer<const V6: bool, C: Packet>(
    ctx: &C,
    cfg: &ClientConfig,
    len: usize,
) -> Result<(), u32> {
    let hlen = if V6 { 40 } else { 20 };
    if V6 {
        write(ctx, ETH, 0x60000000u32.to_be())?;
        write(ctx, ETH + 4, ((len - 40) as u16).to_be())?;
        write(ctx, ETH + 6, IPPROTO_UDP)?;
        write(ctx, ETH + 7, 64u8)?;
        write(ctx, ETH + 8, cfg.local)?;
        write(ctx, ETH + 24, cfg.server)?;
    } else {
        let src = u32::from_ne_bytes([cfg.local[0], cfg.local[1], cfg.local[2], cfg.local[3]]);
        let dst = u32::from_ne_bytes([cfg.server[0], cfg.server[1], cfg.server[2], cfg.server[3]]);
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
    }
    write(ctx, ETH + hlen, cfg.local_port_be)?;
    write(ctx, ETH + hlen + 2, cfg.server_port_be)?;
    write(ctx, ETH + hlen + 4, ((len - hlen) as u16).to_be())?;
    write(ctx, ETH + hlen + 6, 0u16)
}

// Return through BPF's single result register: low 32 bits are the checksum
// sum (at most 1536 * 65535 / 2), high 32 bits hold a nonzero drop reason.
// Rust's Result<u64, u32> must not cross a BPF function-call boundary.
#[inline(always)]
fn xor<const CHECKSUM: bool, C: Packet>(
    ctx: &C,
    offset: usize,
    len: usize,
    seed: u64,
) -> Result<u64, u32> {
    let result = xor_word::<CHECKSUM, C>(ctx, offset, len, seed);
    if result >> 32 != 0 {
        Err((result >> 32) as u32)
    } else {
        Ok(result)
    }
}

#[inline(never)]
fn xor_word<const CHECKSUM: bool, C: Packet>(ctx: &C, offset: usize, len: usize, seed: u64) -> u64 {
    let result = (|| -> Result<u64, u32> {
        if len > wire::MAX_KS_WORDS as usize * 8 {
            return Err(stat::DROP_TOO_BIG);
        }
        let mut sum = 0;
        for word in 0..wire::MAX_KS_WORDS {
            let base = word as usize * 8;
            if base + 8 > len {
                break;
            }
            let key = wire::ks_word(seed, word);
            let pos = offset + base;
            let value = read::<u64, C>(ctx, pos)? ^ key.to_le();
            write(ctx, pos, value)?;
            if CHECKSUM {
                sum += (value & 0xffff)
                    + ((value >> 16) & 0xffff)
                    + ((value >> 32) & 0xffff)
                    + (value >> 48);
            }
        }
        let full = len / 8;
        let key = wire::ks_word(seed, full as u32);
        for byte in 0..7 {
            if byte >= len % 8 {
                break;
            }
            let pos = offset + full * 8 + byte;
            let value = read::<u8, C>(ctx, pos)? ^ (key >> (byte * 8)) as u8;
            write(ctx, pos, value)?;
            if CHECKSUM {
                // Native little-endian checksum words, including zero-padded odd tail.
                sum += (value as u64) << ((byte & 1) * 8);
            }
        }
        Ok(sum)
    })();
    match result {
        Ok(sum) => sum,
        Err(reason) => (reason as u64) << 32,
    }
}

/// Complete the UDP checksum over the ciphertext (summed during XOR), the UDP
/// and wire headers and the IP pseudo header.
#[inline(never)]
fn finish_outer_checksum<C: Packet>(
    ctx: &C,
    len: usize,
    hlen: usize,
    mut sum: u64,
) -> Result<(), u32> {
    let (base, words) = if hlen == 40 {
        (ETH + 8, 16)
    } else {
        (ETH + 12, 4)
    };
    let mut word = 0;
    while word < words {
        sum += read::<u16, C>(ctx, base + word * 2)? as u64;
        word = core::hint::black_box(word + 1);
    }
    // UDP header (checksum zero) and plaintext user ID.
    for word in 0..4 {
        let value = read::<u32, C>(ctx, ETH + hlen + word * 4)?;
        sum += (value & 0xffff) as u64 + (value >> 16) as u64;
    }
    sum += (IPPROTO_UDP as u16).to_be() as u64 + ((len - hlen) as u16).to_be() as u64;
    let check = !csum::fold(sum);
    write(ctx, ETH + hlen + 6, if check == 0 { 0xffff } else { check })
}

#[xdp]
pub fn edup_ingress4(ctx: XdpContext) -> u32 {
    ingress::<false>(&ctx)
}

#[xdp]
pub fn edup_ingress6(ctx: XdpContext) -> u32 {
    ingress::<true>(&ctx)
}

#[inline(always)]
fn ingress<const V6: bool>(ctx: &XdpContext) -> u32 {
    match decap::<V6>(ctx) {
        Ok(action) => action,
        Err(reason) => {
            count(reason);
            xdp_action::XDP_DROP
        }
    }
}

/// Packets other than tunnel data from the server pass unchanged, including
/// KEEPALIVE replies for the client's UDP socket. Errors after decryption
/// starts drop the packet.
#[inline(always)]
fn decap<const V6: bool>(ctx: &XdpContext) -> Result<u32, u32> {
    const PASS: Result<u32, u32> = Ok(xdp_action::XDP_PASS);
    let Some(cfg) = CLIENT_CONFIG.get(0) else {
        return PASS;
    };
    if cfg.physical == 0 || read::<u16, _>(ctx, 12) != Ok(ether::<V6>()) {
        return PASS;
    }
    let hlen = if V6 { 40 } else { 20 };
    let Ok(outer) = (if V6 { ipv6(ctx, ETH) } else { ipv4(ctx, ETH) }) else {
        return PASS;
    };
    if outer.header_len != hlen
        || outer.frag & 0x3fff != 0
        || outer.proto != IPPROTO_UDP
        || outer.len < hlen + 8 + wire::HDR_LEN
    {
        return PASS;
    }
    let addresses = if V6 {
        read::<[u8; 16], _>(ctx, ETH + 8)? == cfg.server
            && read::<[u8; 16], _>(ctx, ETH + 24)? == cfg.local
    } else {
        read::<[u8; 4], _>(ctx, ETH + 12)?
            == [cfg.server[0], cfg.server[1], cfg.server[2], cfg.server[3]]
            && read::<[u8; 4], _>(ctx, ETH + 16)?
                == [cfg.local[0], cfg.local[1], cfg.local[2], cfg.local[3]]
    };
    if !addresses
        || read::<u16, _>(ctx, ETH + hlen)? != cfg.server_port_be
        || read::<u16, _>(ctx, ETH + hlen + 2)? != cfg.local_port_be
        || u16::from_be(read::<u16, _>(ctx, ETH + hlen + 4)?) as usize != outer.len - hlen
        || i64::from_be(read::<i64, _>(ctx, ETH + hlen + 8)?) != cfg.user
        || outer.len - hlen - 16 > wire::MAX_KS_WORDS as usize * 8
    {
        return PASS;
    }
    let seed = wire::ks_seed(&Key {
        k0: cfg.key0,
        k1: cfg.key1,
    });
    let typ = read::<u8, _>(ctx, ETH + hlen + 16)? ^ wire::ks_word(seed, 0) as u8;
    if typ != if V6 { wire::TYPE_IPV6 } else { wire::TYPE_DATA } {
        return PASS;
    }
    let header = hlen + 8 + wire::HDR_LEN;
    let overhead = overhead::<V6>();
    xor::<false, _>(ctx, ETH + hlen + 16, outer.len - hlen - 16, seed)?;
    if V6 {
        unpack_ipv6(ctx, ETH + header, outer.len - header, &cfg.local)?;
    } else {
        unpack_ipv4(ctx, ETH + header, outer.len - header, &cfg.local)?;
    }
    let inner = if V6 {
        ipv6(ctx, ETH + overhead)?
    } else {
        ipv4(ctx, ETH + overhead)?
    };
    if inner.len + overhead != outer.len {
        return Err(stat::DROP_BAD);
    }
    let l4 = transport(ctx, &inner, V6, false)?;
    if V6 {
        replace_local6(
            ctx,
            inner.proto == IPPROTO_UDP,
            l4.check_offset,
            &[0; 16],
            &cfg.local,
        )?;
    } else {
        let local = u32::from_ne_bytes([cfg.local[0], cfg.local[1], cfg.local[2], cfg.local[3]]);
        replace_local4(ctx, inner.proto, l4.check_offset, 0, local)?;
    }
    if inner.proto == IPPROTO_TCP && l4.flags & 2 != 0 {
        clamp_mss(ctx, l4.offset, cfg.mtu - if V6 { 60 } else { 40 })?;
    }
    trim(ctx, ETH + outer.len)?;
    let mac = read::<[u8; 12], _>(ctx, 0)?;
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, overhead as i32) } != 0 {
        return Err(stat::DROP_ADJUST);
    }
    write(ctx, 0, mac)?;
    write(ctx, 12, ether::<V6>())?;
    count(stat::RX_TUNNEL);
    PASS
}

#[inline(always)]
fn trim(ctx: &XdpContext, len: usize) -> Result<(), u32> {
    let current = ctx.data_end() - ctx.data();
    if len > current {
        return Err(stat::DROP_BAD);
    }
    if len < current && unsafe { bpf_xdp_adjust_tail(ctx.ctx, len as i32 - current as i32) } != 0 {
        return Err(stat::DROP_ADJUST);
    }
    Ok(())
}

/// Rebuild the IPv4 header in discarded tunnel-header space, so transport
/// bytes and options stay in place. The local address is the destination.
#[inline(never)]
fn unpack_ipv4(ctx: &XdpContext, compact: usize, len: usize, local: &[u8; 16]) -> Result<(), u32> {
    if len < wire::IPV4_META_LEN || len > 65525 {
        return Err(stat::DROP_BAD);
    }
    let peer = read::<u32, _>(ctx, compact)?;
    let id = read::<u16, _>(ctx, compact + 4)?;
    let flags = read::<u8, _>(ctx, compact + 6)?;
    let tos = read::<u8, _>(ctx, compact + 7)?;
    let ttl_proto = read::<u16, _>(ctx, compact + 8)?;
    let options = (flags & 15) as usize * 4;
    if flags & 0xb0 != 0 || options > 40 || len < wire::IPV4_META_LEN + options {
        return Err(stat::DROP_BAD);
    }
    let offset = compact - wire::IPV4_SAVING;
    write(
        ctx,
        offset,
        u16::from_ne_bytes([0x45 + options as u8 / 4, tos]),
    )?;
    write(ctx, offset + 2, ((len + wire::IPV4_SAVING) as u16).to_be())?;
    write(ctx, offset + 4, id)?;
    write(ctx, offset + 6, u16::from_ne_bytes([flags & 0x40, 0]))?;
    write(ctx, offset + 8, ttl_proto)?;
    write(ctx, offset + 10, 0u16)?;
    write(ctx, offset + 12, peer)?;
    write(ctx, offset + 16, [local[0], local[1], local[2], local[3]])?;
    let mut sum = 0u64;
    let mut i = 0;
    while i < 30 {
        if i * 2 >= 20 + options {
            break;
        }
        sum += read::<u16, _>(ctx, offset + i * 2)? as u64;
        i = core::hint::black_box(i + 1);
    }
    write(ctx, offset + 10, !csum::fold(sum))
}

#[inline(never)]
fn unpack_ipv6(ctx: &XdpContext, compact: usize, len: usize, local: &[u8; 16]) -> Result<(), u32> {
    if len < wire::IPV6_META_LEN || len - wire::IPV6_META_LEN > 65535 {
        return Err(stat::DROP_BAD);
    }
    let peer = read::<[u8; 16], _>(ctx, compact)?;
    let fields = read::<u32, _>(ctx, compact + 16)?;
    if fields.to_be() & 0xf0000000 != 0 {
        return Err(stat::DROP_BAD);
    }
    let next_hop = read::<u16, _>(ctx, compact + 20)?;
    let offset = compact - wire::IPV6_SAVING;
    write(ctx, offset, fields | 0x60000000u32.to_be())?;
    write(
        ctx,
        offset + 4,
        ((len - wire::IPV6_META_LEN) as u16).to_be(),
    )?;
    write(ctx, offset + 6, next_hop)?;
    write(ctx, offset + 8, peer)?;
    write(ctx, offset + 24, *local)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
