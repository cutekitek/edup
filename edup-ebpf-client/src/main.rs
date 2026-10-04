//! Linux client datapath for `"mode": "xdp"`.
//!
//! - `edup_classify*` (TC ingress, LAN interfaces of a router) looks up each
//!   source in the permanent client table `CLIENTS` and stores the client's
//!   mode in the top byte of the packet mark, which survives forwarding and
//!   masquerading up to the egress hook.
//! - `edup_egress*` (TC egress, physical interface) applies the mode: bypassed
//!   clients continue unchanged, proxied clients go to the segmentation veth.
//!   Other traffic looks up each destination in `ROUTES`: bypassed packets
//!   continue unchanged; proxied packets go to the veth; unknown destinations
//!   go through the TUN device to userspace, which stores the route and
//!   re-injects the packet. Without a recent userspace heartbeat, or while a
//!   lookup stays unanswered, packets follow the standard route.
//! - `edup_encap*` (TC ingress, veth peer) receives segmented packets with
//!   complete checksums, encapsulates them and sends them to the server.
//! - `edup_ingress*` (XDP, Ethernet physical interface) and `edup_decap*_l3`
//!   (TC ingress, physical interface without a link-layer header, such as
//!   PPPoE) decapsulate server packets into ordinary packets for the local
//!   stack.
//!
//! `_l3` programs serve interfaces whose packets start at the IP header.
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

mod packet;

use aya_ebpf::{
    bindings::{
        BPF_CSUM_LEVEL_RESET, BPF_NOEXIST, TC_ACT_SHOT, TC_ACT_UNSPEC, bpf_adj_room_mode,
        xdp_action,
    },
    helpers::{
        bpf_csum_level, bpf_ktime_get_ns, bpf_redirect, bpf_redirect_neigh, bpf_skb_change_head,
        bpf_skb_change_tail, bpf_xdp_adjust_head, bpf_xdp_adjust_tail,
    },
    macros::{classifier, map, xdp},
    maps::{Array, LpmTrie, LruHashMap, PerCpuArray, lpm_trie::Key as Prefix},
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
/// Source prefix -> MODE_PROXY or MODE_BYPASS.
#[map]
static CLIENTS: LpmTrie<[u8; 16], u32> = LpmTrie::with_max_entries(CLIENT_ENTRIES, 0);
/// Destinations that keep the standard route even for proxied clients, and
/// need no lookup: the networks of the host's interfaces, such as a LAN or a
/// point-to-point peer, and the host's own addresses.
#[map]
static SYSTEM: LpmTrie<[u8; 16], u32> = LpmTrie::with_max_entries(SYSTEM_ENTRIES, 0);
/// CLOCK_MONOTONIC nanoseconds of the last userspace iteration.
#[map]
static HEARTBEAT: Array<u64> = Array::with_max_entries(1, 0);
/// The key's stream words, filled by userspace.
#[map]
static KEYSTREAM: Array<Keystream> = Array::with_max_entries(1, 0);
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

/// Whether the packet is of the tunnel's family. `L2` is the link-layer
/// header length: 14 for Ethernet, 0 for devices without one.
#[inline(always)]
fn family_is<const V6: bool, const L2: usize>(ctx: &TcContext) -> bool {
    if L2 == ETH {
        ctx.load::<u16>(12).ok() == Some(ether::<V6>())
    } else {
        ctx.skb.protocol() as u16 == ether::<V6>()
    }
}

#[inline(always)]
const fn bits<const V6: bool>() -> u32 {
    if V6 { 128 } else { 32 }
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
pub fn edup_classify4(ctx: TcContext) -> i32 {
    classify::<false, ETH>(&ctx).unwrap_or(TC_ACT_UNSPEC)
}

#[classifier]
pub fn edup_classify6(ctx: TcContext) -> i32 {
    classify::<true, ETH>(&ctx).unwrap_or(TC_ACT_UNSPEC)
}

#[classifier]
pub fn edup_classify4_l3(ctx: TcContext) -> i32 {
    classify::<false, 0>(&ctx).unwrap_or(TC_ACT_UNSPEC)
}

#[classifier]
pub fn edup_classify6_l3(ctx: TcContext) -> i32 {
    classify::<true, 0>(&ctx).unwrap_or(TC_ACT_UNSPEC)
}

/// Source and destination of a packet of the tunnel's family.
#[inline(always)]
fn addresses<const V6: bool, const L2: usize>(
    ctx: &TcContext,
) -> Result<Option<([u8; 16], [u8; 16])>, ()> {
    if !family_is::<V6, L2>(ctx) {
        return Ok(None);
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    if V6 {
        src = ctx.load(L2 + 8).map_err(|_| ())?;
        dst = ctx.load(L2 + 24).map_err(|_| ())?;
    } else {
        src[..4].copy_from_slice(&ctx.load::<[u8; 4]>(L2 + 12).map_err(|_| ())?);
        dst[..4].copy_from_slice(&ctx.load::<[u8; 4]>(L2 + 16).map_err(|_| ())?);
    }
    Ok(Some((src, dst)))
}

/// Multicast and broadcast destinations keep their link-local handling.
#[inline(always)]
fn multicast<const V6: bool>(dst: &[u8; 16]) -> bool {
    if V6 { dst[0] == 0xff } else { dst[0] >= 224 }
}

#[inline(always)]
fn alive(now: u64) -> bool {
    let heartbeat = HEARTBEAT.get(0).copied().unwrap_or(0);
    heartbeat != 0 && now.saturating_sub(heartbeat) < HEARTBEAT_TIMEOUT_NS
}

/// Stores the source's client mode in the mark's top byte, keeping the other
/// bits; sources missing from the table follow the destination rules. For
/// those, unknown destinations are looked up here, before routing and
/// masquerading: userspace re-injects the packet as it arrived, so connection
/// tracking sees it only once.
#[inline(always)]
fn classify<const V6: bool, const L2: usize>(ctx: &TcContext) -> Result<i32, ()> {
    let cfg = CLIENT_CONFIG.get(0).ok_or(())?;
    let Some((src, dst)) = addresses::<V6, L2>(ctx)? else {
        return Ok(TC_ACT_UNSPEC);
    };
    let mode = CLIENTS
        .get(Prefix::new(bits::<V6>(), src))
        .copied()
        .unwrap_or(MODE_RULES as u32);
    // One 32-bit store: the verifier rejects narrower context writes, which
    // LLVM would otherwise use for the changed byte.
    unsafe {
        let mark = core::ptr::addr_of_mut!((*ctx.skb.skb).mark);
        core::ptr::write_volatile(mark, *mark & !MODE_MASK | mode << MODE_SHIFT);
    }
    // Local and on-link destinations need no route.
    if mode != MODE_RULES as u32
        || cfg.physical == 0
        || multicast::<V6>(&dst)
        || dst == cfg.server
        || SYSTEM.get(Prefix::new(bits::<V6>(), dst)).is_some()
    {
        return Ok(TC_ACT_UNSPEC);
    }
    let now = unsafe { bpf_ktime_get_ns() };
    match cached(&dst, now, alive(now)) {
        Cached::Lookup => lookup(cfg),
        _ => Ok(TC_ACT_UNSPEC),
    }
}

#[classifier]
pub fn edup_egress4(ctx: TcContext) -> i32 {
    egress::<false, ETH>(&ctx).unwrap_or(TC_ACT_UNSPEC)
}

#[classifier]
pub fn edup_egress6(ctx: TcContext) -> i32 {
    egress::<true, ETH>(&ctx).unwrap_or(TC_ACT_UNSPEC)
}

#[classifier]
pub fn edup_egress4_l3(ctx: TcContext) -> i32 {
    egress::<false, 0>(&ctx).unwrap_or(TC_ACT_UNSPEC)
}

#[classifier]
pub fn edup_egress6_l3(ctx: TcContext) -> i32 {
    egress::<true, 0>(&ctx).unwrap_or(TC_ACT_UNSPEC)
}

#[inline(always)]
fn fallback() -> Result<i32, ()> {
    count(stat::FALLBACK);
    Ok(TC_ACT_UNSPEC)
}

#[inline(always)]
fn lookup(cfg: &ClientConfig) -> Result<i32, ()> {
    count(stat::LOOKUP);
    // The TUN device takes packets from either kind of interface.
    Ok(unsafe { bpf_redirect(cfg.tun, 0) } as i32)
}

/// What the route cache says about a destination.
enum Cached {
    Proxy,
    Bypass,
    /// Ask userspace; a pending request is recorded.
    Lookup,
    /// Unanswered, or not to be asked: the standard route.
    Fallback,
}

/// `ask`: a missing or pending route may be requested.
#[inline(always)]
fn cached(dst: &[u8; 16], now: u64, ask: bool) -> Cached {
    let Some(entry) = ROUTES.get_ptr_mut(dst) else {
        if !ask {
            return Cached::Fallback;
        }
        let pending = RouteEntry {
            since_ns: now,
            action: ROUTE_PENDING,
            _pad: 0,
        };
        // Losing a race to another CPU leaves an equivalent request.
        let _ = ROUTES.insert(dst, &pending, BPF_NOEXIST as u64);
        return Cached::Lookup;
    };
    let route = unsafe { core::ptr::read_volatile(entry) };
    match route.action {
        ROUTE_BYPASS => Cached::Bypass,
        ROUTE_PROXY => Cached::Proxy,
        _ => {
            let age = now.saturating_sub(route.since_ns);
            if !ask || (LOOKUP_WAIT_NS..LOOKUP_RETRY_NS).contains(&age) {
                return Cached::Fallback;
            }
            if age >= LOOKUP_RETRY_NS {
                // Userspace replaces the whole entry when it answers; this
                // write can only renew a request that is still pending.
                unsafe {
                    core::ptr::write_volatile(core::ptr::addr_of_mut!((*entry).since_ns), now)
                };
            }
            Cached::Lookup
        }
    }
}

/// Sends a proxied packet into the segmentation veth, which carries Ethernet
/// frames: interfaces without a link-layer header get an empty one.
#[inline(always)]
fn proxy<const V6: bool, const L2: usize>(ctx: &TcContext, cfg: &ClientConfig) -> Result<i32, ()> {
    count(stat::PROXY);
    if L2 == 0 {
        if unsafe { bpf_skb_change_head(ctx.skb.skb, ETH as u32, 0) } != 0 {
            count(stat::DROP_ADJUST);
            return Ok(TC_ACT_SHOT as i32);
        }
        let mut header = [0u8; ETH];
        header[12..].copy_from_slice(&ether::<V6>().to_ne_bytes());
        if ctx.store(0, &header, 0).is_err() {
            count(stat::DROP_ADJUST);
            return Ok(TC_ACT_SHOT as i32);
        }
    }
    Ok(unsafe { bpf_redirect(cfg.segment, 0) } as i32)
}

/// Err and TC_ACT_UNSPEC leave the packet to the standard route.
#[inline(always)]
fn egress<const V6: bool, const L2: usize>(ctx: &TcContext) -> Result<i32, ()> {
    let cfg = CLIENT_CONFIG.get(0).ok_or(())?;
    if cfg.physical == 0 {
        return Ok(TC_ACT_UNSPEC);
    }
    let Some((src, dst)) = addresses::<V6, L2>(ctx)? else {
        return Ok(TC_ACT_UNSPEC);
    };
    // The tunnel itself and anything else for the server always take the
    // standard route.
    if multicast::<V6>(&dst) || dst == cfg.server {
        return Ok(TC_ACT_UNSPEC);
    }
    // Userspace re-injects packets after storing their route; they follow
    // the destination rules. Classified packets were looked up before.
    let mark = unsafe { (*ctx.skb.skb).mark };
    let reinjected = mark & !MODE_MASK == cfg.mark;
    let (mode, classified) = match (mark >> MODE_SHIFT) as u8 {
        _ if reinjected => (MODE_RULES, false),
        mode @ (MODE_RULES | MODE_PROXY | MODE_BYPASS) => (mode, true),
        _ => (cfg.local_mode, false),
    };
    if mode == MODE_BYPASS {
        count(stat::BYPASS);
        return Ok(TC_ACT_UNSPEC);
    }
    let now = unsafe { bpf_ktime_get_ns() };
    if !alive(now) {
        return fallback();
    }
    if mode == MODE_PROXY {
        if SYSTEM.get(Prefix::new(bits::<V6>(), dst)).is_some() {
            count(stat::BYPASS);
            return Ok(TC_ACT_UNSPEC);
        }
        // Replies carry no local address: only masqueraded traffic fits.
        if src != cfg.local {
            count(stat::FOREIGN_SOURCE);
            return Ok(TC_ACT_UNSPEC);
        }
        return proxy::<V6, L2>(ctx, cfg);
    }
    // Other local addresses keep the standard route.
    if src != cfg.local {
        return Ok(TC_ACT_UNSPEC);
    }
    // Never look up a re-injected packet again, even if the LRU has
    // already evicted its route.
    match cached(&dst, now, !reinjected && !classified) {
        Cached::Bypass => {
            count(stat::BYPASS);
            Ok(TC_ACT_UNSPEC)
        }
        Cached::Proxy => proxy::<V6, L2>(ctx, cfg),
        Cached::Lookup => lookup(cfg),
        Cached::Fallback => fallback(),
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
    let sum = xor::<true, _>(ctx, ETH + hlen + 16, outer - hlen - 16)?;
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
// sum, high 32 bits hold a nonzero drop reason. Rust's Result<u64, u32> must
// not cross a BPF function-call boundary.
#[inline(always)]
fn xor<const CHECKSUM: bool, C: Packet>(ctx: &C, offset: usize, len: usize) -> Result<u64, u32> {
    let result = xor_word::<CHECKSUM, C>(ctx, offset, len);
    if result >> 32 != 0 {
        Err((result >> 32) as u32)
    } else {
        Ok(result)
    }
}

/// One 8-byte load from a packet address checked by the caller. LLVM splits
/// possibly unaligned accesses into single bytes; the kernel takes them
/// whole where unaligned access is cheap (x86-64, arm64) and rejects the
/// program elsewhere.
#[inline(always)]
fn load64(ptr: usize) -> u64 {
    let value;
    // SAFETY: the verifier checks the access against the packet bounds.
    unsafe {
        core::arch::asm!(
            "{0} = *(u64 *)({1} + 0)",
            lateout(reg) value,
            in(reg) ptr,
            options(nostack, readonly, preserves_flags)
        )
    };
    value
}

#[inline(always)]
fn store64(ptr: usize, value: u64) {
    // SAFETY: as in load64.
    unsafe {
        core::arch::asm!(
            "*(u64 *)({0} + 0) = {1}",
            in(reg) ptr,
            in(reg) value,
            options(nostack, preserves_flags)
        )
    };
}

/// XORs `len` bytes at `offset` with the keystream. This loop is most of the
/// datapath's work: per word one table load, packet load and packet store.
#[inline(never)]
fn xor_word<const CHECKSUM: bool, C: Packet>(ctx: &C, offset: usize, len: usize) -> u64 {
    let result = (|| -> Result<u64, u32> {
        let ks = KEYSTREAM.get(0).ok_or(stat::DROP_BAD)?;
        if len > wire::MAX_KS_WORDS as usize * 8 {
            return Err(stat::DROP_TOO_BIG);
        }
        if offset > 128 {
            return Err(stat::DROP_BAD);
        }
        let start = ctx.start() + offset;
        let end = ctx.end();
        let full = len / 8;
        let mut sum = 0;
        for word in 0..wire::MAX_KS_WORDS as usize {
            if word >= full {
                break;
            }
            let ptr = start + word * 8;
            if ptr + 8 > end {
                return Err(stat::DROP_BAD);
            }
            let key = *ks.words.get(word).ok_or(stat::DROP_BAD)?;
            let value = load64(ptr) ^ key.to_le();
            store64(ptr, value);
            if CHECKSUM {
                // 32-bit halves keep the one's complement sum of 16-bit words.
                sum += (value & 0xffff_ffff) + (value >> 32);
            }
        }
        let key = *ks.words.get(full).ok_or(stat::DROP_BAD)?;
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
        // Below 2^32, which the result's error half requires.
        sum = (sum & 0xffff_ffff) + (sum >> 32);
        sum = (sum & 0xffff_ffff) + (sum >> 32);
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
    match ingress_result::<V6>(ctx) {
        Ok(action) => action,
        Err(reason) => {
            count(reason);
            xdp_action::XDP_DROP
        }
    }
}

#[inline(always)]
fn ingress_result<const V6: bool>(ctx: &XdpContext) -> Result<u32, u32> {
    const PASS: Result<u32, u32> = Ok(xdp_action::XDP_PASS);
    let Some(cfg) = CLIENT_CONFIG.get(0) else {
        return PASS;
    };
    if read::<u16, _>(ctx, 12) != Ok(ether::<V6>()) {
        return PASS;
    }
    let Some(outer) = tunnel::<V6, ETH, _>(ctx, cfg)? else {
        return PASS;
    };
    decap::<V6, ETH, _>(ctx, cfg, &outer)?;
    trim(ctx, ETH + outer.len)?;
    let mac = read::<[u8; 12], _>(ctx, 0)?;
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, overhead::<V6>() as i32) } != 0 {
        return Err(stat::DROP_ADJUST);
    }
    write(ctx, 0, mac)?;
    write(ctx, 12, ether::<V6>())?;
    count(stat::RX_TUNNEL);
    PASS
}

#[classifier]
pub fn edup_decap4_l3(ctx: TcContext) -> i32 {
    ingress_l3::<false>(&ctx)
}

#[classifier]
pub fn edup_decap6_l3(ctx: TcContext) -> i32 {
    ingress_l3::<true>(&ctx)
}

/// TC ingress decapsulation for interfaces without a link-layer header,
/// whose packets start at the IP header. Generic XDP would treat their first
/// bytes as an Ethernet header after the packet start moves.
#[inline(always)]
fn ingress_l3<const V6: bool>(ctx: &TcContext) -> i32 {
    match ingress_l3_result::<V6>(ctx) {
        Ok(action) => action,
        Err(reason) => {
            count(reason);
            TC_ACT_SHOT as i32
        }
    }
}

/// Bytes the tunnel checks read before the whole packet is made linear.
const TUNNEL_HEADER: u32 = 40 + 8 + wire::HDR_LEN as u32 + 1;

#[inline(always)]
fn ingress_l3_result<const V6: bool>(ctx: &TcContext) -> Result<i32, u32> {
    const PASS: Result<i32, u32> = Ok(TC_ACT_UNSPEC);
    let Some(cfg) = CLIENT_CONFIG.get(0) else {
        return PASS;
    };
    let len = ctx.len();
    if ctx.skb.protocol() as u16 != ether::<V6>()
        || ctx.skb.pull_data(len.min(TUNNEL_HEADER)).is_err()
        || tunnel::<V6, 0, _>(ctx, cfg)?.is_none()
        || ctx.skb.pull_data(len).is_err()
    {
        return PASS;
    }
    // Pulling invalidates packet pointers; check the header again.
    let Some(outer) = tunnel::<V6, 0, _>(ctx, cfg)? else {
        return PASS;
    };
    decap::<V6, 0, _>(ctx, cfg, &outer)?;
    if len as usize > outer.len
        && unsafe { bpf_skb_change_tail(ctx.skb.skb, outer.len as u32, 0) } != 0
    {
        return Err(stat::DROP_ADJUST);
    }
    if ctx
        .skb
        .adjust_room(
            -(overhead::<V6>() as i32),
            bpf_adj_room_mode::BPF_ADJ_ROOM_MAC,
            0,
        )
        .is_err()
    {
        return Err(stat::DROP_ADJUST);
    }
    // The inner checksums are complete; no stale receive checksum applies.
    unsafe { bpf_csum_level(ctx.skb.skb, BPF_CSUM_LEVEL_RESET as u64) };
    count(stat::RX_TUNNEL);
    if cfg.inbound == 0 {
        return PASS;
    }
    // GRO ran before this hook. Through the veth, whose peer merges inner
    // TCP segments, the stack forwards one packet instead of dozens.
    if unsafe { bpf_skb_change_head(ctx.skb.skb, ETH as u32, 0) } != 0 {
        return Err(stat::DROP_ADJUST);
    }
    let mut header = [0u8; ETH];
    header[..6].copy_from_slice(&cfg.inbound_mac);
    header[12..].copy_from_slice(&ether::<V6>().to_ne_bytes());
    if ctx.store(0, &header, 0).is_err() {
        return Err(stat::DROP_ADJUST);
    }
    Ok(unsafe { bpf_redirect(cfg.inbound, 0) } as i32)
}

/// The outer IP header of tunnel data from the server, if this is one.
/// Other packets pass unchanged, including KEEPALIVE replies for the
/// client's UDP socket.
#[inline(always)]
fn tunnel<const V6: bool, const L2: usize, C: Packet>(
    ctx: &C,
    cfg: &ClientConfig,
) -> Result<Option<Ip>, u32> {
    if cfg.physical == 0 {
        return Ok(None);
    }
    let hlen = if V6 { 40 } else { 20 };
    let Ok(outer) = (if V6 { ipv6(ctx, L2) } else { ipv4(ctx, L2) }) else {
        return Ok(None);
    };
    if outer.header_len != hlen
        || outer.frag & 0x3fff != 0
        || outer.proto != IPPROTO_UDP
        || outer.len < hlen + 8 + wire::HDR_LEN
    {
        return Ok(None);
    }
    let addresses = if V6 {
        read::<[u8; 16], _>(ctx, L2 + 8)? == cfg.server
            && read::<[u8; 16], _>(ctx, L2 + 24)? == cfg.local
    } else {
        read::<[u8; 4], _>(ctx, L2 + 12)?
            == [cfg.server[0], cfg.server[1], cfg.server[2], cfg.server[3]]
            && read::<[u8; 4], _>(ctx, L2 + 16)?
                == [cfg.local[0], cfg.local[1], cfg.local[2], cfg.local[3]]
    };
    if !addresses
        || read::<u16, _>(ctx, L2 + hlen)? != cfg.server_port_be
        || read::<u16, _>(ctx, L2 + hlen + 2)? != cfg.local_port_be
        || u16::from_be(read::<u16, _>(ctx, L2 + hlen + 4)?) as usize != outer.len - hlen
        || i64::from_be(read::<i64, _>(ctx, L2 + hlen + 8)?) != cfg.user
        || outer.len - hlen - 16 > wire::MAX_KS_WORDS as usize * 8
    {
        return Ok(None);
    }
    let seed = wire::ks_seed(&Key {
        k0: cfg.key0,
        k1: cfg.key1,
    });
    let typ = read::<u8, _>(ctx, L2 + hlen + 16)? ^ wire::ks_word(seed, 0) as u8;
    if typ != if V6 { wire::TYPE_IPV6 } else { wire::TYPE_DATA } {
        return Ok(None);
    }
    Ok(Some(outer))
}

/// Decrypts and unpacks tunnel data in place; the inner packet then starts
/// `overhead` bytes later. Errors after decryption starts drop the packet.
#[inline(always)]
fn decap<const V6: bool, const L2: usize, C: Packet>(
    ctx: &C,
    cfg: &ClientConfig,
    outer: &Ip,
) -> Result<(), u32> {
    let hlen = if V6 { 40 } else { 20 };
    let header = hlen + 8 + wire::HDR_LEN;
    let overhead = overhead::<V6>();
    xor::<false, _>(ctx, L2 + hlen + 16, outer.len - hlen - 16)?;
    if V6 {
        unpack_ipv6(ctx, L2 + header, outer.len - header, &cfg.local)?;
    } else {
        unpack_ipv4(ctx, L2 + header, outer.len - header, &cfg.local)?;
    }
    let inner = if V6 {
        ipv6(ctx, L2 + overhead)?
    } else {
        ipv4(ctx, L2 + overhead)?
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
    Ok(())
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
fn unpack_ipv4<C: Packet>(
    ctx: &C,
    compact: usize,
    len: usize,
    local: &[u8; 16],
) -> Result<(), u32> {
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
fn unpack_ipv6<C: Packet>(
    ctx: &C,
    compact: usize,
    len: usize,
    local: &[u8; 16],
) -> Result<(), u32> {
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
