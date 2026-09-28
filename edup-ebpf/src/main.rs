#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![allow(internal_features)]

mod ipv4;
mod ipv6;
mod nat;
mod packet;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_ktime_get_ns, bpf_xdp_adjust_head, bpf_xdp_adjust_tail},
    macros::{map, xdp},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, ProgramArray},
    programs::XdpContext,
};
use edup_common::{
    csum,
    maps::*,
    wire::{self, Key},
};
use packet::*;

#[map]
static PROTOCOLS: ProgramArray = ProgramArray::with_max_entries(2, 0);
#[map]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);
#[map]
static USER_IDS: HashMap<i64, u16> = HashMap::with_max_entries(MAX_USERS, 0);
#[map]
static USERS: Array<User> = Array::with_max_entries(MAX_USERS, 0);
#[map]
static ENDPOINTS: HashMap<u16, Endpoint> = HashMap::with_max_entries(MAX_USERS, 0);
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
    let family = match read::<u16>(&ctx, 12) {
        Ok(ether) if ether == 0x0800u16.to_be() => 0,
        Ok(ether) if ether == 0x86ddu16.to_be() => 1,
        _ => {
            count(stat::PASS);
            return xdp_action::XDP_PASS;
        }
    };
    unsafe {
        let _ = PROTOCOLS.tail_call(&ctx, family);
    }
    count(stat::DROP_BAD_HDR);
    xdp_action::XDP_DROP
}

#[inline(always)]
fn handle<const V6: bool>(ctx: XdpContext) -> u32 {
    match process::<V6>(&ctx) {
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
fn process<const V6: bool>(ctx: &XdpContext) -> Result<u32, u32> {
    if ctx.data() + ETH + 20 > ctx.data_end() {
        return pass();
    }
    let Some(cfg) = CONFIG.get(0) else {
        return pass();
    };
    if cfg.port_be == 0 {
        return pass();
    }
    let ether = read::<u16>(ctx, 12)?;
    if ether
        != if V6 {
            0x86ddu16.to_be()
        } else {
            0x0800u16.to_be()
        }
    {
        return pass();
    }
    let (ip, server, nat) = if V6 {
        let Ok(ip) = ipv6(ctx, ETH) else {
            return pass();
        };
        let dst = read::<[u8; 16]>(ctx, ETH + 24)?;
        (
            ip,
            cfg.server_ip6 != [0; 16] && dst == cfg.server_ip6,
            cfg.nat_ip6 != [0; 16] && dst == cfg.nat_ip6,
        )
    } else {
        let Ok(ip) = ipv4(ctx, ETH) else {
            return pass();
        };
        if ip.frag & 0x1fff != 0 {
            return pass();
        }
        let server = ip.dst == cfg.server_ip_be;
        let nat = ip.dst == cfg.nat_ip_be;
        (ip, server, nat)
    };
    let l4 = ETH + ip.header_len;
    if server
        && ip.proto == IPPROTO_UDP
        && ip.len >= ip.header_len + 8
        && read::<u16>(ctx, l4 + 2)? == cfg.port_be
    {
        count(stat::RX_TUNNEL);
        return from_client::<V6>(ctx, cfg, &ip);
    }
    if !nat {
        return pass();
    }
    from_internet::<V6>(ctx, cfg, &ip)
}

// Family specialization keeps the IPv4 and IPv6 verifier paths independent.
#[inline(always)]
fn from_internet<const V6: bool>(ctx: &XdpContext, cfg: &Config, ip: &Ip) -> Result<u32, u32> {
    let Ok(transport) = transport(ctx, ip, false) else {
        return pass();
    };
    let key = NatInKey {
        pub_port_be: transport.port,
        proto: ip.proto,
        v6: ip.v6,
    };
    let now = unsafe { bpf_ktime_get_ns() };
    let Some(mapping) = nat::inbound(&key, transport.flags, now) else {
        return pass();
    };
    count(stat::RX_INTERNET);
    to_client::<V6>(ctx, cfg, ip, &transport, &mapping)
}

// Return through BPF's single result register: low 32 bits are the checksum
// sum (at most 1536 * 65535 / 2), high 32 bits hold a nonzero drop reason.
// Rust's Result<u64, u32> must not cross a BPF function-call boundary.
#[inline(always)]
fn xor<const CHECKSUM: bool>(
    ctx: &XdpContext,
    offset: usize,
    len: usize,
    seed: u64,
) -> Result<u64, u32> {
    let result = xor_word::<CHECKSUM>(ctx, offset, len, seed);
    if result >> 32 != 0 {
        Err((result >> 32) as u32)
    } else {
        Ok(result)
    }
}

#[inline(never)]
fn xor_word<const CHECKSUM: bool>(ctx: &XdpContext, offset: usize, len: usize, seed: u64) -> u64 {
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
            let value = read::<u64>(ctx, pos)? ^ key.to_le();
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
            let value = read::<u8>(ctx, pos)? ^ (key >> (byte * 8)) as u8;
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

/// Complete the UDP checksum over the ciphertext, UDP header and IP pseudo
/// header. Nonzero outer checksums allow the receiving stack to use UDP GRO/URO.
/// Ciphertext's sum is accumulated during XOR, avoiding another packet walk.
#[inline(never)]
fn finish_outer_checksum(
    ctx: &XdpContext,
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
        sum += read::<u16>(ctx, base + word * 2)? as u64;
        word = core::hint::black_box(word + 1);
    }
    // UDP header (checksum zero) and plaintext user ID.
    for word in 0..4 {
        let value = read::<u32>(ctx, ETH + hlen + word * 4)?;
        sum += (value & 0xffff) as u64 + (value >> 16) as u64;
    }
    sum += (IPPROTO_UDP as u16).to_be() as u64 + ((len - hlen) as u16).to_be() as u64;
    let check = !csum::fold(sum);
    write(ctx, ETH + hlen + 6, if check == 0 { 0xffff } else { check })
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
fn endpoint(ctx: &XdpContext, user: u16, outer: &Ip, port: u16, now: u64) -> Result<Endpoint, u32> {
    let mut value = Endpoint {
        port_be: port,
        v6: outer.v6,
        mac: swapped_mac(ctx)?,
        ..Endpoint::default()
    };
    if outer.v6 != 0 {
        value.address = read(ctx, ETH + 8)?;
    } else {
        value.address[..4].copy_from_slice(&outer.src.to_ne_bytes());
    }
    ENDPOINTS
        .insert(user, value, 0)
        .map_err(|_| stat::DROP_NO_ENDPOINT)?;
    if let Some(ptr) = USERS.get_ptr_mut(user as u32) {
        unsafe {
            // Kept for backwards-compatible IPv4 endpoint inspection.
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*ptr).endpoint),
                if outer.v6 == 0 {
                    User::pack_endpoint(outer.src, port)
                } else {
                    0
                },
            );
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).last_seen_ns), now);
        }
    }
    Ok(value)
}

#[inline(always)]
fn from_client<const V6: bool>(ctx: &XdpContext, cfg: &Config, outer: &Ip) -> Result<u32, u32> {
    let hlen = if V6 { 40 } else { 20 };
    let header = hlen + 8 + wire::HDR_LEN;
    let overhead = header
        - if V6 {
            wire::IPV6_SAVING
        } else {
            wire::IPV4_SAVING
        };
    // IPv4 options and IPv6 extension/fragment headers are unsupported.
    if outer.header_len != hlen || outer.frag & 0x3fff != 0 || outer.len < header {
        return Err(stat::DROP_BAD_HDR);
    }
    if outer.len > cfg.max_frame as usize {
        return Err(stat::DROP_TOO_BIG);
    }
    let udp_len = u16::from_be(read::<u16>(ctx, ETH + hlen + 4)?) as usize;
    if udp_len != outer.len - hlen || (outer.v6 != 0 && read::<u16>(ctx, ETH + hlen + 6)? == 0) {
        return Err(stat::DROP_BAD_HDR);
    }
    // Look up the public ID before reading or XORing the packet body.
    let id = i64::from_be(read::<i64>(ctx, ETH + hlen + 8)?);
    let user = unsafe { USER_IDS.get(&id) }
        .copied()
        .ok_or(stat::DROP_UNKNOWN_USER)?;
    let u = USERS.get(user as u32).ok_or(stat::DROP_UNKNOWN_USER)?;
    if u.enabled == 0 || u.id != id {
        return Err(stat::DROP_UNKNOWN_USER);
    }
    let seed = wire::ks_seed(&Key {
        k0: u.key0,
        k1: u.key1,
    });
    let typ = read::<u8>(ctx, ETH + hlen + 16)? ^ wire::ks_word(seed, 0) as u8;
    let port = read::<u16>(ctx, ETH + hlen)?;
    if port == 0 {
        return Err(stat::DROP_BAD_HDR);
    }
    let now = unsafe { bpf_ktime_get_ns() };
    let mac = swapped_mac(ctx)?;
    if typ == wire::TYPE_KEEPALIVE {
        if outer.len != header {
            return Err(stat::DROP_BAD_HDR);
        }
        let ep = endpoint(ctx, user, outer, port, now)?;
        trim(ctx, ETH + outer.len)?;
        write_outer::<V6>(ctx, cfg, outer.len, &ep)?;
        write(ctx, 0, mac)?;
        let ciphertext = read::<u8>(ctx, ETH + hlen + 16)?;
        finish_outer_checksum(ctx, outer.len, hlen, ciphertext as u64)?;
        count(stat::KEEPALIVE);
        return Ok(xdp_action::XDP_TX);
    }
    if typ != if V6 { wire::TYPE_IPV6 } else { wire::TYPE_DATA } {
        return Err(stat::DROP_BAD_HDR);
    }
    xor::<false>(ctx, ETH + hlen + 16, outer.len - hlen - 16, seed)?;
    if V6 {
        unpack_ipv6(ctx, ETH + header, outer.len - header)?;
    } else {
        unpack_ipv4(ctx, ETH + header, outer.len - header)?;
    }
    let inner = if V6 {
        ipv6(ctx, ETH + overhead)
    } else {
        ipv4(ctx, ETH + overhead)
    }
    .map_err(|_| stat::DROP_BAD_INNER)?;
    if inner.len + overhead != outer.len {
        return Err(stat::DROP_BAD_INNER);
    }
    if V6 && cfg.nat_ip6 == [0; 16] {
        return Err(stat::DROP_PROTO);
    }
    let l4 = transport(ctx, &inner, true)?;
    if inner.ttl <= 1 {
        return Err(stat::DROP_TTL);
    }
    let key = NatOutKey {
        inner_port_be: l4.port,
        proto: inner.proto,
        v6: inner.v6,
        user,
        _pad: [0; 2],
    };
    endpoint(ctx, user, outer, port, now)?;
    let public_port = nat::outbound(&key, l4.flags, cfg, now);
    if public_port == 0 {
        return Err(stat::DROP_NAT_FULL);
    }
    if V6 {
        translate6(
            ctx,
            &inner,
            &l4,
            &cfg.nat_ip6,
            public_port as u32 | (1 << 16),
        )?;
    } else {
        translate(ctx, &inner, &l4, cfg.nat_ip_be, public_port, true)?;
    }
    trim(ctx, ETH + outer.len)?;
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, overhead as i32) } != 0 {
        return Err(stat::DROP_ADJUST);
    }
    let mut mac = mac;
    let gateway = if V6 {
        cfg.gateway6_mac
    } else {
        cfg.gateway_mac
    };
    if gateway != [0; 6] {
        mac[..6].copy_from_slice(&gateway);
    }
    write(ctx, 0, mac)?;
    write(
        ctx,
        12,
        if V6 {
            0x86ddu16.to_be()
        } else {
            0x0800u16.to_be()
        },
    )?;
    count(stat::TX_INTERNET);
    Ok(xdp_action::XDP_TX)
}

/// Reuse discarded tunnel-header space: L4 and options stay at their offsets.
#[inline(never)]
fn unpack_ipv4(ctx: &XdpContext, compact: usize, len: usize) -> Result<(), u32> {
    if len < wire::IPV4_META_LEN || len > 65525 {
        return Err(stat::DROP_BAD_INNER);
    }
    let peer = read::<u32>(ctx, compact)?;
    let id = read::<u16>(ctx, compact + 4)?;
    let flags = read::<u8>(ctx, compact + 6)?;
    let tos = read::<u8>(ctx, compact + 7)?;
    let ttl_proto = read::<u16>(ctx, compact + 8)?;
    let options = (flags & 15) as usize * 4;
    if flags & 0xb0 != 0 || options > 40 || len < wire::IPV4_META_LEN + options {
        return Err(stat::DROP_BAD_INNER);
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
    write(ctx, offset + 12, 0u32)?;
    write(ctx, offset + 16, peer)?;
    let mut sum = 0u64;
    let mut i = 0;
    while i < 30 {
        if i * 2 >= 20 + options {
            break;
        }
        sum += read::<u16>(ctx, offset + i * 2)? as u64;
        i = core::hint::black_box(i + 1);
    }
    write(ctx, offset + 10, !csum::fold(sum))
}

/// DNAT has normalized the destination/checksum to zero. Keep only peer metadata.
#[inline(never)]
fn pack_ipv4(ctx: &XdpContext, ip: &Ip) -> Result<(), u32> {
    if ip.header_len > 60 || ip.frag & 0xbfff != 0 {
        return Err(stat::DROP_BAD_INNER);
    }
    let peer = read::<u32>(ctx, ip.offset + 12)?;
    let id = read::<u16>(ctx, ip.offset + 4)?;
    let tos = read::<u8>(ctx, ip.offset + 1)?;
    let ttl_proto = read::<u16>(ctx, ip.offset + 8)?;
    let flags = ((ip.frag >> 8) as u8 & 0x40) | (ip.header_len as u8 / 4 - 5);
    let offset = ip.offset + wire::IPV4_SAVING;
    write(ctx, offset, peer)?;
    write(ctx, offset + 4, id)?;
    write(ctx, offset + 6, flags)?;
    write(ctx, offset + 7, tos)?;
    write(ctx, offset + 8, ttl_proto)
}

/// Expand into discarded outer-header space without moving the transport bytes.
#[inline(never)]
fn unpack_ipv6(ctx: &XdpContext, compact: usize, len: usize) -> Result<(), u32> {
    if len < wire::IPV6_META_LEN || len - wire::IPV6_META_LEN > 65535 {
        return Err(stat::DROP_BAD_INNER);
    }
    let peer = read::<[u8; 16]>(ctx, compact)?;
    let fields = read::<u32>(ctx, compact + 16)?;
    if fields.to_be() & 0xf0000000 != 0 {
        return Err(stat::DROP_BAD_INNER);
    }
    let next_hop = read::<u16>(ctx, compact + 20)?;
    let offset = compact - wire::IPV6_SAVING;
    write(ctx, offset, fields | 0x60000000u32.to_be())?;
    write(
        ctx,
        offset + 4,
        ((len - wire::IPV6_META_LEN) as u16).to_be(),
    )?;
    write(ctx, offset + 6, next_hop)?;
    write(ctx, offset + 8, [0u8; 16])?;
    write(ctx, offset + 24, peer)
}

#[inline(never)]
fn pack_ipv6(ctx: &XdpContext, ip: &Ip) -> Result<(), u32> {
    let peer = read::<[u8; 16]>(ctx, ip.offset + 8)?;
    let fields = read::<u32>(ctx, ip.offset)? & 0x0fffffffu32.to_be();
    let next_hop = read::<u16>(ctx, ip.offset + 6)?;
    let offset = ip.offset + wire::IPV6_SAVING;
    write(ctx, offset, peer)?;
    write(ctx, offset + 16, fields)?;
    write(ctx, offset + 20, next_hop)
}

#[inline(always)]
fn to_client<const V6: bool>(
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
    let ep = ENDPOINTS
        .get_ptr(&mapping.user)
        .ok_or(stat::DROP_NO_ENDPOINT)?;
    let ep = unsafe { core::ptr::read_volatile(ep) };
    if ep.v6 != u8::from(V6) {
        return Err(stat::DROP_NO_ENDPOINT);
    }
    let hlen = if V6 { 40 } else { 20 };
    let overhead = hlen + 8 + wire::HDR_LEN
        - if V6 {
            wire::IPV6_SAVING
        } else {
            wire::IPV4_SAVING
        };
    let len = ip.len + overhead;
    if len > cfg.max_frame as usize || len - hlen - 16 > wire::MAX_KS_WORDS as usize * 8 {
        return Err(stat::DROP_TOO_BIG);
    }
    if V6 {
        translate6(ctx, ip, l4, &[0; 16], mapping.inner_port_be as u32)?;
    } else {
        translate(ctx, ip, l4, 0, mapping.inner_port_be, false)?;
    }
    if V6 {
        pack_ipv6(ctx, ip)?;
    } else {
        pack_ipv4(ctx, ip)?;
    }
    trim(ctx, ETH + ip.len)?;
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(overhead as i32)) } != 0 {
        return Err(stat::DROP_ADJUST);
    }
    write(ctx, 0, ep.mac)?;
    write_outer::<V6>(ctx, cfg, len, &ep)?;
    write(ctx, ETH + hlen + 8, u.id.to_be())?;
    write(
        ctx,
        ETH + hlen + 16,
        if V6 { wire::TYPE_IPV6 } else { wire::TYPE_DATA },
    )?;
    let sum = xor::<true>(
        ctx,
        ETH + hlen + 16,
        len - hlen - 16,
        wire::ks_seed(&Key {
            k0: u.key0,
            k1: u.key1,
        }),
    )?;
    finish_outer_checksum(ctx, len, hlen, sum)?;
    count(stat::TX_TUNNEL);
    Ok(xdp_action::XDP_TX)
}

#[inline(never)]
fn write_outer<const V6: bool>(
    ctx: &XdpContext,
    cfg: &Config,
    len: usize,
    ep: &Endpoint,
) -> Result<(), u32> {
    let hlen = if V6 { 40 } else { 20 };
    if V6 {
        write(ctx, 12, 0x86ddu16.to_be())?;
        write(ctx, ETH, 0x60000000u32.to_be())?;
        write(ctx, ETH + 4, ((len - 40) as u16).to_be())?;
        write(ctx, ETH + 6, IPPROTO_UDP)?;
        write(ctx, ETH + 7, 64u8)?;
        write(ctx, ETH + 8, cfg.server_ip6)?;
        write(ctx, ETH + 24, ep.address)?;
    } else {
        let src = cfg.server_ip_be;
        let dst = u32::from_ne_bytes([ep.address[0], ep.address[1], ep.address[2], ep.address[3]]);
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
        write(ctx, 12, 0x0800u16.to_be())?;
        write(ctx, ETH, words)?;
        write(ctx, ETH + 10, csum::ipv4_header(&words))?;
    }
    write(ctx, ETH + hlen, cfg.port_be)?;
    write(ctx, ETH + hlen + 2, ep.port_be)?;
    write(ctx, ETH + hlen + 4, ((len - hlen) as u16).to_be())?;
    write(ctx, ETH + hlen + 6, 0u16)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
