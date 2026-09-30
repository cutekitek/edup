//! RFC 8439 ChaCha20-Poly1305 applied to packet bytes in place, in one pass.
//! The associated data is the 16-byte wire header; the tag follows it and the
//! ciphertext follows the tag. Handshake packets instead authenticate the
//! header plus the 16-byte nonce after the tag, with no ciphertext.
//!
//! Two kernel limits shape this module:
//! - Verification cost: a 1500-byte packet needs 24 ChaCha20 blocks, and the
//!   verifier walks every iteration of every path. `edup_crypt` (one packet)
//!   and `edup_block` (one 64-byte block) are BTF global functions, which the
//!   kernel verifies once with arbitrary arguments instead of at each call.
//! - Stack: all frames of a call chain share 512 bytes. The data path's own
//!   frame leaves too little, so sealing and opening run in separate
//!   tail-called programs (see `maps::program`), and the register-hungry
//!   ChaCha20 rounds and Poly1305 arithmetic are leaf functions.
//!
//! State lives in a per-CPU map entry, which also carries what the programs
//! after a tail call need. XDP runs with preemption disabled, so nothing else
//! on this CPU can use the entry while a packet is processed.
use crate::packet::bytes;
use aya_ebpf::{bindings::xdp_md, macros::map, maps::PerCpuArray, programs::XdpContext};
use edup_common::{
    crypto::{self, Key, Poly1305},
    maps::stat,
    wire,
};

#[repr(C)]
pub struct Pass {
    pub key: Key,
    pub nonce: [u32; 3],
    /// Packet offset of the wire header (user ID).
    pub header: u32,
    /// Ciphertext length; the ciphertext starts at `header + HDR_LEN`.
    pub len: u32,
    seal: u32,
    /// Ones'-complement word sum of the ciphertext, for the outer checksum.
    pub sum: u64,
    /// HChaCha20 key input (handshake).
    pub spare: Key,
    tag: [u32; 4],
    ks: [u32; 16],
    poly: Poly1305,
    // Carried across tail calls.
    /// Outer IP packet length and header length (20 or 40).
    pub frame: u32,
    pub hlen: u32,
    /// Statistic counted after sealing.
    pub stat: u32,
    pub user: u32,
    pub phase: u32,
    /// Nonzero: the first packet of a pending session.
    pub pending: u32,
    pub typ: u32,
    pub counter: u64,
}

#[map]
static PASSES: PerCpuArray<Pass> = PerCpuArray::with_max_entries(1, 0);

/// This CPU's pass state. Fill `key`, `nonce`, `header` and `len`, then call
/// [`edup_crypt`] or [`handshake`].
#[inline(always)]
pub fn pass() -> Result<*mut Pass, u32> {
    PASSES.get_ptr_mut(0).ok_or(stat::DROP_ADJUST)
}

const BLOCKS: u32 = (wire::MAX_BODY / 64) as u32;
/// Largest header offset: Ethernet, IPv6 and UDP headers.
const MAX_HEADER: usize = 14 + 40 + 8;

/// The header offset, bounded before any pointer arithmetic. Map contents
/// are unknown to the verifier, and LLVM may otherwise compare a 32-bit copy
/// after forming the pointer from the 64-bit value.
#[inline(always)]
fn header(pass: &Pass) -> Result<usize, u32> {
    let header = core::hint::black_box(pass.header as usize);
    if header > MAX_HEADER {
        return Err(stat::DROP_BAD_HDR);
    }
    Ok(header)
}

#[inline(always)]
fn status(result: Result<(), u32>) -> u32 {
    match result {
        Ok(()) => 0,
        Err(reason) => reason,
    }
}

/// ChaCha20 input state, written word by word: a 64-byte temporary would
/// land on the stack.
#[inline(always)]
#[allow(clippy::manual_memcpy)] // explicit word stores, no memcpy
fn load_state(ks: &mut [u32; 16], key: &Key, counter: u32, nonce: &[u32; 3]) {
    for i in 0..4 {
        ks[i] = crypto::SIGMA[i];
    }
    for i in 0..8 {
        ks[4 + i] = key[i];
    }
    ks[12] = counter;
    for i in 0..3 {
        ks[13 + i] = nonce[i];
    }
}

/// Keystream block `counter` into `pass.ks` (global function: verified once
/// instead of once per block of every packet length).
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn edup_keystream(counter: u32) -> u32 {
    match PASSES.get_ptr_mut(0) {
        Some(pass) => {
            keystream(unsafe { &mut *pass }, counter);
            0
        }
        None => stat::DROP_ADJUST,
    }
}

/// Keystream block `counter` into `pass.ks`. Leaf: the rounds' register
/// spills stay out of the callers' frames.
#[inline(never)]
fn keystream(pass: &mut Pass, counter: u32) {
    let Pass { key, nonce, ks, .. } = pass;
    load_state(ks, key, counter, nonce);
    crypto::permute(ks);
    // Reload the input from the map rather than keeping copies alive (and
    // spilled) across the rounds.
    let key = unsafe { core::ptr::read_volatile(key) };
    let nonce = unsafe { core::ptr::read_volatile(nonce) };
    crypto::add_state(ks, &key, counter, &nonce);
}

/// `pass.key = HChaCha20(pass.spare, input)`.
#[inline(never)]
pub fn hchacha(pass: &mut Pass, input: &[u32; 4]) {
    let Pass { spare, ks, .. } = pass;
    load_state(ks, spare, input[0], &[input[1], input[2], input[3]]);
    crypto::permute(ks);
    let out = crypto::hchacha_output(ks);
    pass.key = out;
}

/// Poly1305 key from keystream block 0 (leaf).
#[inline(never)]
fn poly_init(pass: &mut Pass) {
    let ks = &pass.ks;
    pass.poly = Poly1305::new(&[ks[0], ks[1], ks[2], ks[3], ks[4], ks[5], ks[6], ks[7]]);
}

/// Absorb one 16-byte block given as two little-endian words (leaf).
#[inline(never)]
fn absorb(pass: &mut Pass, a: u64, b: u64) {
    pass.poly.block(crypto::words(a, b));
}

/// `pass.tag = Poly1305 tag` (leaf).
#[inline(never)]
fn finalize(pass: &mut Pass) {
    pass.tag = pass.poly.finish();
}

#[inline(always)]
fn fold64(v: u64) -> u64 {
    (v & 0xffff) + ((v >> 16) & 0xffff) + ((v >> 32) & 0xffff) + (v >> 48)
}

#[inline(always)]
unsafe fn load(p: *const u8) -> u64 {
    unsafe { core::ptr::read_unaligned(p as *const u64) }
}

#[inline(always)]
unsafe fn store(p: *mut u8, v: u64) {
    unsafe { core::ptr::write_unaligned(p as *mut u64, v) }
}

#[inline(always)]
fn pair(ks: &[u32; 16], w: usize) -> u64 {
    ks[w] as u64 | (ks[w + 1] as u64) << 32
}

/// Transform a final partial 16-byte unit bytewise with keystream words
/// `w..w + 4`. The last unit's keystream is not needed afterwards, so the
/// zero-padded ciphertext words for Poly1305 return in `pass.ks[0..4]`.
#[inline(never)]
fn tail(ctx: &XdpContext, pass: &mut Pass, at: usize, rem: usize, w: usize) -> u32 {
    status((|| {
        let w = w & 12;
        let key = [pair(&pass.ks, w), pair(&pass.ks, w + 2)];
        let seal = pass.seal != 0;
        let (mut c0, mut c1) = (0u64, 0u64);
        for i in 0..15 {
            if i >= rem {
                break;
            }
            let shift = (i % 8) * 8;
            let k = if i < 8 { key[0] } else { key[1] };
            let p = bytes::<1>(ctx, at + i)?;
            let input = unsafe { *p };
            let output = input ^ (k >> shift) as u8;
            unsafe { *p = output };
            let cipher = (if seal { output } else { input }) as u64;
            if i < 8 {
                c0 |= cipher << shift;
            } else {
                c1 |= cipher << shift;
            }
        }
        pass.ks[0] = c0 as u32;
        pass.ks[1] = (c0 >> 32) as u32;
        pass.ks[2] = c1 as u32;
        pass.ks[3] = (c1 >> 32) as u32;
        Ok(())
    })())
}

/// Transform and authenticate the 64-byte block `block` of the current pass
/// with the keystream already in `pass.ks` (global function).
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn edup_block(ctx: *mut xdp_md, block: u32) -> u32 {
    let ctx = XdpContext::new(ctx);
    let Some(pass) = PASSES.get_ptr_mut(0) else {
        return stat::DROP_ADJUST;
    };
    let pass = unsafe { &mut *pass };
    if block >= BLOCKS {
        return stat::DROP_TOO_BIG;
    }
    let header = match header(pass) {
        Ok(header) => header,
        Err(reason) => return reason,
    };
    let len = pass.len as usize;
    let mut pos = block as usize * 64;
    let mut w = 0;
    while w < 16 {
        if pos >= len {
            break;
        }
        let at = header + wire::HDR_LEN + pos;
        let (c0, c1) = if pos + 16 <= len {
            match unit(&ctx, pass, at, w) {
                Ok(c) => c,
                Err(reason) => return reason,
            }
        } else {
            let reason = tail(&ctx, pass, at, len - pos, w);
            if reason != 0 {
                return reason;
            }
            (pair(&pass.ks, 0), pair(&pass.ks, 2))
        };
        absorb(pass, c0, c1);
        // Units start at even offsets and zero padding adds nothing.
        pass.sum += fold64(c0) + fold64(c1);
        pos += 16;
        // Keep the loop rolled: unrolled units spill more stack.
        w = core::hint::black_box(w + 4);
    }
    0
}

/// XOR one full 16-byte unit; returns its ciphertext words.
#[inline(always)]
fn unit(ctx: &XdpContext, pass: &mut Pass, at: usize, w: usize) -> Result<(u64, u64), u32> {
    let w = w & 12;
    let (k0, k1) = (pair(&pass.ks, w), pair(&pass.ks, w + 2));
    let p = bytes::<16>(ctx, at)?;
    let (p0, p1) = unsafe { (load(p), load(p.add(8))) };
    unsafe {
        store(p, p0 ^ k0);
        store(p.add(8), p1 ^ k1);
    }
    Ok(if pass.seal != 0 {
        (p0 ^ k0, p1 ^ k1)
    } else {
        (p0, p1)
    })
}

/// Seal (encrypt, write the tag) or open (decrypt, verify the tag) the pass
/// (global function). Opening decrypts before the comparison, but a forged
/// packet is dropped before the caller changes any state.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn edup_crypt(ctx: *mut xdp_md, seal: u32) -> u32 {
    let raw = ctx;
    let ctx = XdpContext::new(ctx);
    let Some(pass) = PASSES.get_ptr_mut(0) else {
        return stat::DROP_ADJUST;
    };
    let pass = unsafe { &mut *pass };
    let len = pass.len as usize;
    if len > wire::MAX_BODY {
        return stat::DROP_TOO_BIG;
    }
    let header = match header(pass) {
        Ok(header) => header,
        Err(reason) => return reason,
    };
    if let Err(reason) = start(&ctx, pass, header) {
        return reason;
    }
    pass.sum = 0;
    pass.seal = seal;
    let mut block = 0;
    while block < BLOCKS {
        if block as usize * 64 >= len {
            break;
        }
        let mut reason = edup_keystream(block + 1);
        if reason == 0 {
            reason = edup_block(raw, block);
        }
        if reason != 0 {
            return reason;
        }
        block += 1;
    }
    absorb(pass, wire::AAD_LEN as u64, len as u64);
    status(finish(&ctx, pass, header, seal != 0))
}

/// Poly1305 key from keystream block 0, then the header block.
#[inline(always)]
fn start(ctx: &XdpContext, pass: &mut Pass, header: usize) -> Result<(), u32> {
    keystream(pass, 0);
    poly_init(pass);
    let p = bytes::<16>(ctx, header)?;
    let (a, b) = unsafe { (load(p), load(p.add(8))) };
    absorb(pass, a, b);
    Ok(())
}

/// Write the tag (sealing) or compare it with the packet's (opening).
#[inline(always)]
fn finish(ctx: &XdpContext, pass: &mut Pass, header: usize, seal: bool) -> Result<(), u32> {
    finalize(pass);
    let p = bytes::<16>(ctx, header + wire::AAD_LEN)?;
    if seal {
        unsafe { core::ptr::write_unaligned(p as *mut [u32; 4], pass.tag) };
        return Ok(());
    }
    let tag = unsafe { core::ptr::read_unaligned(p as *const [u32; 4]) };
    if crypto::tags_equal(&pass.tag, &tag) {
        Ok(())
    } else {
        Err(stat::DROP_AUTH)
    }
}

/// Seal (write) or verify the tag of a handshake packet: the header and the
/// nonce field after the tag are associated data, and there is no ciphertext.
#[inline(always)]
pub fn handshake(ctx: &XdpContext, pass: &mut Pass, seal: bool) -> Result<(), u32> {
    let header = header(pass)?;
    start(ctx, pass, header)?;
    let p = bytes::<16>(ctx, header + wire::HDR_LEN)?;
    let (a, b) = unsafe { (load(p), load(p.add(8))) };
    absorb(pass, a, b);
    absorb(pass, (wire::AAD_LEN + wire::NONCE_LEN) as u64, 0);
    finish(ctx, pass, header, seal)
}
