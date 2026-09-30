//! NAT_IN owns the lifetime; NAT_OUT is an index, never an authority.
//! Both directions cross-check ownership because either LRU can evict alone.
use crate::{NAT_IN, NAT_OUT, packet::compare_exchange};
use aya_ebpf::bindings::BPF_NOEXIST;
use edup_common::maps::*;

const PROBES: u32 = 64;

#[inline(always)]
fn state(proto: u8, previous: u8, flags: u8) -> u8 {
    if proto != IPPROTO_TCP {
        return ST_OTHER;
    }
    if flags & 0x05 != 0 || previous == ST_TCP_CLOSING {
        ST_TCP_CLOSING
    } else if flags & 0x10 != 0 || previous == ST_TCP_EST {
        ST_TCP_EST
    } else {
        ST_TCP_SYN
    }
}

#[inline(always)]
fn snapshot(key: &NatInKey) -> Option<NatInVal> {
    let ptr = NAT_IN.get_ptr(key)?;
    // Copy immediately; do not hold a reference across map helpers.
    Some(unsafe { core::ptr::read_volatile(ptr) })
}

#[inline(always)]
fn alive(v: &NatInVal, proto: u8, now: u64) -> bool {
    v.last_seen_ns != 0 && now.saturating_sub(v.last_seen_ns) < nat_timeout_ns(proto, v.state)
}

#[inline(always)]
fn owner(v: &NatInVal, key: &NatOutKey) -> bool {
    v.inner_port_be == key.inner_port_be && v.user == key.user
}

#[inline(always)]
fn touch(key: &NatInKey, v: &NatInVal, flags: u8, now: u64) {
    let next_state = state(key.proto, v.state, flags);
    let refresh = now.saturating_sub(v.last_seen_ns) >= TOUCH_INTERVAL_NS;
    // Most established packets change neither field. Avoid another hash map
    // lookup and a shared cache-line write on that hot path. Ownership checks
    // in the caller still run for every packet.
    if !refresh && next_state == v.state {
        return;
    }
    if let Some(ptr) = NAT_IN.get_ptr_mut(key) {
        unsafe {
            // Expiration claims last_seen=0. A racing touch must not resurrect it.
            let timestamp = core::ptr::addr_of_mut!((*ptr).last_seen_ns);
            if refresh {
                let _ = compare_exchange(timestamp, v.last_seen_ns, now);
            }
            if next_state != v.state {
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).state), next_state);
            }
        }
    }
}

#[inline(always)]
fn expire(key: &NatInKey, v: &NatInVal, now: u64) {
    if v.last_seen_ns == 0 || alive(v, key.proto, now) {
        return;
    }
    let Some(ptr) = NAT_IN.get_ptr_mut(key) else {
        return;
    };
    let claimed = unsafe {
        compare_exchange(
            core::ptr::addr_of_mut!((*ptr).last_seen_ns),
            v.last_seen_ns,
            0,
        )
    };
    if claimed {
        // Leave the outbound index stale; outbound lookup checks the owner.
        let _ = NAT_IN.remove(key);
    }
}

#[inline(never)]
pub fn outbound(key: &NatOutKey, flags: u8, cfg: &Config, now: u64) -> u16 {
    if let Some(ptr) = NAT_OUT.get_ptr(key) {
        let port = unsafe { core::ptr::read_volatile(ptr).pub_port_be };
        let reverse = NatInKey {
            pub_port_be: port,
            proto: key.proto,
            v6: key.v6,
        };
        if let Some(v) = snapshot(&reverse) {
            if owner(&v, key) && alive(&v, key.proto, now) {
                touch(&reverse, &v, flags, now);
                return port;
            }
            expire(&reverse, &v, now);
        }
        // Stale after independent LRU eviction, expiry, or port reuse.
        let _ = NAT_OUT.remove(key);
    }
    if cfg.nat_port_min == 0 || cfg.nat_port_min > cfg.nat_port_max {
        return 0;
    }
    let range = cfg.nat_port_max as u32 - cfg.nat_port_min as u32 + 1;
    let hash = mix64(
        mix64(0)
            ^ (key.user as u64) << 32
            ^ (key.inner_port_be as u64) << 16
            ^ (key.proto as u64) << 8
            ^ key.v6 as u64,
    ) as u32;
    let start = hash % range;
    for probe in 0..PROBES {
        if probe >= range {
            break;
        }
        let port = (cfg.nat_port_min as u32 + (start + probe) % range) as u16;
        // Never steal the listening socket, even with an invalid loader config.
        if port.to_be() == cfg.port_be {
            continue;
        }
        let reverse = NatInKey {
            pub_port_be: port.to_be(),
            proto: key.proto,
            v6: key.v6,
        };
        if let Some(v) = snapshot(&reverse) {
            expire(&reverse, &v, now);
        }
        let value = NatInVal {
            last_seen_ns: now,
            inner_port_be: key.inner_port_be,
            user: key.user,
            state: state(key.proto, ST_OTHER, flags),
            _pad: [0; 3],
        };
        if NAT_IN.insert(reverse, value, BPF_NOEXIST as u64).is_err() {
            continue;
        }
        let out = NatOutVal {
            pub_port_be: port.to_be(),
            _pad: 0,
        };
        if NAT_OUT.insert(key, out, BPF_NOEXIST as u64).is_ok() {
            return port.to_be();
        }
        // A concurrent first packet won the index. Discard our reservation and
        // use the winner only if its reverse entry is still owned by this flow.
        let _ = NAT_IN.remove(reverse);
        if let Some(ptr) = NAT_OUT.get_ptr(key) {
            let port = unsafe { core::ptr::read_volatile(ptr).pub_port_be };
            let reverse = NatInKey {
                pub_port_be: port,
                proto: key.proto,
                v6: key.v6,
            };
            if let Some(v) = snapshot(&reverse)
                && owner(&v, key)
                && alive(&v, key.proto, now)
            {
                return port;
            }
        }
        return 0;
    }
    0
}

// Reuse caller scratch slots to stay within older kernels' combined stack limit.
#[inline(always)]
pub fn inbound(key: &NatInKey, flags: u8, now: u64) -> Option<NatInVal> {
    let v = snapshot(key)?;
    if !alive(&v, key.proto, now) {
        expire(key, &v, now);
        return None;
    }
    let forward = NatOutKey {
        inner_port_be: v.inner_port_be,
        proto: key.proto,
        v6: key.v6,
        user: v.user,
        _pad: [0; 2],
    };
    let ptr = NAT_OUT.get_ptr(forward)?;
    if unsafe { core::ptr::read_volatile(ptr).pub_port_be } != key.pub_port_be {
        return None;
    }
    touch(key, &v, flags, now);
    Some(v)
}
