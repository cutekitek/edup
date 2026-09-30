#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![allow(internal_features)]

mod crypt;
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
    crypto, csum,
    maps::*,
    wire::{self, TO_CLIENT, TO_SERVER},
};
use packet::*;

#[map]
static PROTOCOLS: ProgramArray = ProgramArray::with_max_entries(program::COUNT, 0);
#[map]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);
#[map]
static USER_IDS: HashMap<i64, u16> = HashMap::with_max_entries(MAX_USERS, 0);
#[map]
static USERS: Array<User> = Array::with_max_entries(MAX_USERS, 0);
#[map]
static SESSIONS: Array<Session> = Array::with_max_entries(MAX_SESSIONS, 0);
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

/// Decrypt and verify a client packet prepared by `from_client`, then
/// continue in the family's ACCEPT program.
#[xdp]
pub fn edup_open(ctx: XdpContext) -> u32 {
    let result = (|| {
        let reason = crypt::edup_crypt(ctx.ctx, 0);
        if reason != 0 {
            return Err(reason);
        }
        let pass = crypt::pass()?;
        let next = if unsafe { (*pass).hlen } == 40 {
            program::ACCEPT_IPV6
        } else {
            program::ACCEPT_IPV4
        };
        tail(&ctx, next)
    })();
    finish(&ctx, result)
}

/// Encrypt a packet prepared for a client, complete its UDP checksum and send.
#[xdp]
pub fn edup_seal(ctx: XdpContext) -> u32 {
    let result = (|| {
        let reason = crypt::edup_crypt(ctx.ctx, 1);
        if reason != 0 {
            return Err(reason);
        }
        let pass = crypt::pass()?;
        let (frame, hlen, sum, stat) =
            unsafe { ((*pass).frame, (*pass).hlen, (*pass).sum, (*pass).stat) };
        if hlen != 20 && hlen != 40 {
            return Err(stat::DROP_BAD_HDR);
        }
        finish_outer_checksum(&ctx, frame as usize, hlen as usize, sum)?;
        count(stat);
        Ok(xdp_action::XDP_TX)
    })();
    finish(&ctx, result)
}

/// Continue in another program. Returns only if the tail call fails.
#[inline(always)]
fn tail(ctx: &XdpContext, index: u32) -> Result<u32, u32> {
    unsafe {
        let _ = PROTOCOLS.tail_call(ctx, index);
    }
    Err(stat::DROP_ADJUST)
}

#[inline(always)]
fn handle<const V6: bool>(ctx: XdpContext) -> u32 {
    finish(&ctx, process::<V6>(&ctx))
}

#[inline(always)]
fn finish(ctx: &XdpContext, result: Result<u32, u32>) -> u32 {
    match result {
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

/// Complete the UDP checksum over the ciphertext, wire header, UDP header and
/// IP pseudo header. Nonzero outer checksums allow the receiver to use UDP
/// GRO/URO. The ciphertext's sum is accumulated while sealing, avoiding
/// another packet walk.
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
    // UDP header (checksum zero), cleartext header and tag.
    let mut word = 0;
    while word < (8 + wire::HDR_LEN) / 8 {
        sum += fold64(read::<u64>(ctx, ETH + hlen + word * 8)?);
        word = core::hint::black_box(word + 1);
    }
    sum += (IPPROTO_UDP as u16).to_be() as u64 + ((len - hlen) as u16).to_be() as u64;
    let check = !csum::fold(sum);
    write(ctx, ETH + hlen + 6, if check == 0 { 0xffff } else { check })
}

#[inline(always)]
fn fold64(v: u64) -> u64 {
    (v & 0xffff) + ((v >> 16) & 0xffff) + ((v >> 32) & 0xffff) + (v >> 48)
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

/// The packet's source as a reply destination.
#[inline(always)]
fn source(ctx: &XdpContext, outer: &Ip, port: u16) -> Result<Endpoint, u32> {
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
    Ok(value)
}

/// Learn the return path. Only for authenticated, non-replayed session
/// packets: anything else could redirect the user's traffic.
#[inline(always)]
fn endpoint(ctx: &XdpContext, user: u16, outer: &Ip, port: u16, now: u64) -> Result<Endpoint, u32> {
    let value = source(ctx, outer, port)?;
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

/// Accept a counter at most once per session (lock-free; see
/// `crypto::replay_update`). Contention beyond a few retries drops the packet.
#[inline(always)]
fn replay(slot: *mut Session, counter: u64) -> Result<(), u32> {
    let index = crypto::replay_index(counter, WINDOW_SLOTS) & (WINDOW_SLOTS - 1);
    let ptr = unsafe { core::ptr::addr_of_mut!((*slot).window[index]) };
    for _ in 0..4 {
        let old = unsafe { core::ptr::read_volatile(ptr) };
        let new = crypto::replay_update(old, counter).ok_or(stat::DROP_REPLAY)?;
        if unsafe { compare_exchange(ptr, old, new) } {
            return Ok(());
        }
    }
    Err(stat::DROP_REPLAY)
}

/// Whether `counter` is the highest accepted so far in this session.
#[inline(always)]
fn newest(slot: *mut Session, counter: u64) -> bool {
    let ptr = unsafe { core::ptr::addr_of_mut!((*slot).newest) };
    for _ in 0..4 {
        let old = unsafe { core::ptr::read_volatile(ptr) };
        if counter <= old {
            return false;
        }
        if unsafe { compare_exchange(ptr, old, counter) } {
            return true;
        }
    }
    false
}

/// The endpoint learned from the session's newest packet.
#[inline(always)]
fn learned<const V6: bool>(user: u16) -> Result<Endpoint, u32> {
    let ep = ENDPOINTS.get_ptr(&user).ok_or(stat::DROP_NO_ENDPOINT)?;
    let ep = unsafe { core::ptr::read_volatile(ep) };
    if ep.v6 != u8::from(V6) {
        return Err(stat::DROP_NO_ENDPOINT);
    }
    Ok(ep)
}

/// Allocate a unique server-to-client counter (the nonce) for this session.
#[inline(always)]
fn next_counter(slot: *mut Session) -> Result<u64, u32> {
    let counter =
        unsafe { fetch_increment(core::ptr::addr_of_mut!((*slot).tx)) }.ok_or(stat::DROP_ADJUST)?;
    if counter > wire::MAX_COUNTER {
        return Err(stat::DROP_NO_SESSION);
    }
    Ok(counter)
}

#[inline(always)]
fn session_slot(user: u16, phase: u32) -> Result<*mut Session, u32> {
    SESSIONS
        .get_ptr_mut(user as u32 * 2 + (phase & 1))
        .ok_or(stat::DROP_NO_SESSION)
}

/// Type, flags and counter: bytes 8..16 of the wire header.
#[inline(always)]
fn write_meta(ctx: &XdpContext, hlen: usize, typ: u8, phase: u32, counter: u64) -> Result<(), u32> {
    let meta = (typ as u64) << 56 | ((phase & 1) as u64) << 48 | counter;
    write(ctx, ETH + hlen + 16, meta.to_be())
}

/// Entry of the INIT programs. The data path tail-calls them, so they start
/// with a fresh stack instead of adding to the data path's 512-byte budget.
#[inline(always)]
fn handshake_entry<const V6: bool>(ctx: XdpContext) -> u32 {
    finish(&ctx, handshake::<V6>(&ctx))
}

#[inline(always)]
fn accept_entry<const V6: bool>(ctx: XdpContext) -> u32 {
    finish(&ctx, accept::<V6>(&ctx))
}

/// INIT: verify it with K1 = HChaCha20(user key, client nonce), derive a fresh
/// session key into the inactive slot and answer with RESPONSE. The active
/// session and learned endpoint stay untouched: INIT is replayable.
#[inline(always)]
fn handshake<const V6: bool>(ctx: &XdpContext) -> Result<u32, u32> {
    let cfg = CONFIG.get(0).ok_or(stat::DROP_BAD_HDR)?;
    let hlen = if V6 { 40 } else { 20 };
    let outer = if V6 { ipv6(ctx, ETH) } else { ipv4(ctx, ETH) }.map_err(|_| stat::DROP_BAD_HDR)?;
    let header = ETH + hlen + 8;
    // Re-check what the data path checked before the tail call. INIT has zero
    // flags and counter.
    if outer.header_len != hlen
        || outer.frag & 0x3fff != 0
        || outer.proto != IPPROTO_UDP
        || outer.len != hlen + 8 + wire::HANDSHAKE_LEN
        || read::<u16>(ctx, ETH + hlen + 2)? != cfg.port_be
        || u64::from_be(read::<u64>(ctx, header + 8)?) != (wire::TYPE_INIT as u64) << 56
    {
        return Err(stat::DROP_BAD_HDR);
    }
    let port = read::<u16>(ctx, ETH + hlen)?;
    let id = i64::from_be(read::<i64>(ctx, header)?);
    let user = unsafe { USER_IDS.get(&id) }
        .copied()
        .ok_or(stat::DROP_UNKNOWN_USER)?;
    let u = USERS
        .get_ptr_mut(user as u32)
        .ok_or(stat::DROP_UNKNOWN_USER)?;
    if unsafe { (*u).enabled == 0 || (*u).id != id } || port == 0 {
        return Err(stat::DROP_UNKNOWN_USER);
    }
    let client = read::<[u32; 4]>(ctx, header + wire::HDR_LEN)?;
    let pass = unsafe { &mut *crypt::pass()? };
    pass.spare = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*u).key)) };
    pass.nonce = crypto::nonce(TO_SERVER, 0);
    pass.header = header as u32;
    pass.len = 0;
    crypt::hchacha(pass, &client);
    crypt::handshake(ctx, pass, false)?;
    let phase = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*u).phase)) } ^ 1;
    let slot = session_slot(user, phase)?;
    let serial = unsafe { fetch_increment(core::ptr::addr_of_mut!((*u).handshakes)) }
        .ok_or(stat::DROP_ADJUST)?;
    let server = [
        cfg.salt as u32,
        (cfg.salt >> 32) as u32,
        serial as u32,
        (serial >> 32) as u32,
    ];
    pass.spare = pass.key;
    crypt::hchacha(pass, &server);
    unsafe {
        // Invalidate first: a concurrent reader then sees a non-pending slot
        // or a torn key, and either way fails closed.
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*slot).state), SESSION_EMPTY);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*slot).key), pass.key);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*slot).tx), 1);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*slot).newest), 0);
        let mut i = 0;
        while i < WINDOW_SLOTS {
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*slot).window[i]), 0);
            i = core::hint::black_box(i + 1);
        }
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*slot).state), SESSION_PENDING);
    }
    let mac = swapped_mac(ctx)?;
    let reply = source(ctx, &outer, port)?;
    trim(ctx, ETH + outer.len)?;
    write_meta(ctx, hlen, wire::TYPE_RESPONSE, phase, 0)?;
    write(ctx, header + wire::HDR_LEN, server)?;
    pass.nonce = crypto::nonce(TO_CLIENT, 0);
    crypt::handshake(ctx, pass, true)?;
    write_outer::<V6>(ctx, cfg, outer.len, &reply)?;
    write(ctx, 0, mac)?;
    let mut nonce_sum = 0u64;
    for word in server {
        nonce_sum += (word & 0xffff) as u64 + (word >> 16) as u64;
    }
    finish_outer_checksum(ctx, outer.len, hlen, nonce_sum)?;
    count(stat::HANDSHAKE);
    Ok(xdp_action::XDP_TX)
}

#[inline(always)]
fn from_client<const V6: bool>(ctx: &XdpContext, cfg: &Config, outer: &Ip) -> Result<u32, u32> {
    let hlen = if V6 { 40 } else { 20 };
    let header = hlen + 8 + wire::HDR_LEN;
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
    // Look up the public ID before any cryptographic work.
    let id = i64::from_be(read::<i64>(ctx, ETH + hlen + 8)?);
    let user = unsafe { USER_IDS.get(&id) }
        .copied()
        .ok_or(stat::DROP_UNKNOWN_USER)?;
    let u = USERS
        .get_ptr_mut(user as u32)
        .ok_or(stat::DROP_UNKNOWN_USER)?;
    if unsafe { (*u).enabled == 0 || (*u).id != id } {
        return Err(stat::DROP_UNKNOWN_USER);
    }
    let port = read::<u16>(ctx, ETH + hlen)?;
    if port == 0 {
        return Err(stat::DROP_BAD_HDR);
    }
    let meta = u64::from_be(read::<u64>(ctx, ETH + hlen + 16)?);
    let typ = (meta >> 56) as u8;
    let phase = (meta >> 48) as u8;
    let counter = meta & wire::MAX_COUNTER;
    if typ == wire::TYPE_INIT {
        return tail(
            ctx,
            if V6 {
                program::HANDSHAKE_IPV6
            } else {
                program::HANDSHAKE_IPV4
            },
        );
    }
    if phase > 1 {
        return Err(stat::DROP_BAD_HDR);
    }
    if typ == wire::TYPE_KEEPALIVE {
        if outer.len != header {
            return Err(stat::DROP_BAD_HDR);
        }
    } else if typ != if V6 { wire::TYPE_IPV6 } else { wire::TYPE_DATA } {
        return Err(stat::DROP_BAD_HDR);
    }
    // The active slot, or the pending one whose first packet confirms it.
    let active = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*u).phase)) };
    let pending = phase as u32 != active;
    let slot = session_slot(user, phase as u32)?;
    let state = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*slot).state)) };
    if state
        != if pending {
            SESSION_PENDING
        } else {
            SESSION_ACTIVE
        }
    {
        return Err(stat::DROP_NO_SESSION);
    }
    let pass = crypt::pass()?;
    unsafe {
        (*pass).key = core::ptr::read_volatile(core::ptr::addr_of!((*slot).key));
        (*pass).nonce = crypto::nonce(TO_SERVER, counter);
        (*pass).header = (ETH + hlen + 8) as u32;
        (*pass).len = (outer.len - header) as u32;
        (*pass).frame = outer.len as u32;
        (*pass).hlen = hlen as u32;
        (*pass).user = user as u32;
        (*pass).phase = phase as u32;
        (*pass).pending = pending as u32;
        (*pass).typ = typ as u32;
        (*pass).counter = counter;
    }
    tail(ctx, program::OPEN)
}

/// After `edup_open` authenticated the packet: replay check, session
/// confirmation, endpoint learning, then KEEPALIVE reply or NAT forwarding.
#[inline(always)]
fn accept<const V6: bool>(ctx: &XdpContext) -> Result<u32, u32> {
    let cfg = CONFIG.get(0).ok_or(stat::DROP_BAD_HDR)?;
    let pass = crypt::pass()?;
    let (user, phase, pending, typ, counter, frame) = unsafe {
        (
            (*pass).user as u16,
            (*pass).phase,
            (*pass).pending != 0,
            (*pass).typ as u8,
            (*pass).counter,
            (*pass).frame as usize,
        )
    };
    let hlen = if V6 { 40 } else { 20 };
    let header = hlen + 8 + wire::HDR_LEN;
    let overhead = header
        - if V6 {
            wire::IPV6_SAVING
        } else {
            wire::IPV4_SAVING
        };
    let outer = if V6 { ipv6(ctx, ETH) } else { ipv4(ctx, ETH) }.map_err(|_| stat::DROP_BAD_HDR)?;
    let outer = &outer;
    if outer.len != frame || outer.header_len != hlen || outer.len < header {
        return Err(stat::DROP_BAD_HDR);
    }
    let u = USERS
        .get_ptr_mut(user as u32)
        .ok_or(stat::DROP_UNKNOWN_USER)?;
    let slot = session_slot(user, phase)?;
    let port = read::<u16>(ctx, ETH + hlen)?;
    replay(slot, counter)?;
    if pending {
        let state = unsafe { core::ptr::addr_of_mut!((*slot).state) };
        // Another CPU may have confirmed the same session concurrently.
        if !unsafe { compare_exchange(state, SESSION_PENDING, SESSION_ACTIVE) }
            && unsafe { core::ptr::read_volatile(state) } != SESSION_ACTIVE
        {
            return Err(stat::DROP_NO_SESSION);
        }
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*u).phase), phase) };
    }
    let roam = newest(slot, counter);
    let now = unsafe { bpf_ktime_get_ns() };
    let mac = swapped_mac(ctx)?;
    if typ == wire::TYPE_KEEPALIVE {
        // A delayed KEEPALIVE is answered at the known endpoint, not at an
        // address an on-path attacker may have rewritten.
        let ep = if roam {
            endpoint(ctx, user, outer, port, now)?
        } else {
            learned::<V6>(user)?
        };
        trim(ctx, ETH + outer.len)?;
        write_outer::<V6>(ctx, cfg, outer.len, &ep)?;
        write(ctx, 0, mac)?;
        let reply = next_counter(slot)?;
        write_meta(ctx, hlen, wire::TYPE_KEEPALIVE, phase, reply)?;
        // Same key and header, an empty body; frame and hlen are unchanged.
        unsafe {
            (*pass).nonce = crypto::nonce(TO_CLIENT, reply);
            (*pass).len = 0;
            (*pass).stat = stat::KEEPALIVE;
        }
        return tail(ctx, program::SEAL);
    }
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
    if roam {
        endpoint(ctx, user, outer, port, now)?;
    }
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
    let phase = unsafe { core::ptr::read_volatile(&u.phase) };
    let slot = session_slot(mapping.user, phase)?;
    if unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*slot).state)) } != SESSION_ACTIVE {
        return Err(stat::DROP_NO_SESSION);
    }
    let ep = learned::<V6>(mapping.user)?;
    let hlen = if V6 { 40 } else { 20 };
    let overhead = hlen + 8 + wire::HDR_LEN
        - if V6 {
            wire::IPV6_SAVING
        } else {
            wire::IPV4_SAVING
        };
    let len = ip.len + overhead;
    let body = len - hlen - 8 - wire::HDR_LEN;
    if len > cfg.max_frame as usize || body > wire::MAX_BODY {
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
    let counter = next_counter(slot)?;
    write_meta(
        ctx,
        hlen,
        if V6 { wire::TYPE_IPV6 } else { wire::TYPE_DATA },
        phase,
        counter,
    )?;
    let pass = crypt::pass()?;
    unsafe {
        (*pass).key = core::ptr::read_volatile(core::ptr::addr_of!((*slot).key));
        (*pass).nonce = crypto::nonce(TO_CLIENT, counter);
        (*pass).header = (ETH + hlen + 8) as u32;
        (*pass).len = body as u32;
        (*pass).frame = len as u32;
        (*pass).hlen = hlen as u32;
        (*pass).stat = stat::TX_TUNNEL;
    }
    tail(ctx, program::SEAL)
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
