//! ChaCha20, HChaCha20 and Poly1305 (RFC 8439, draft-irtf-cfrg-xchacha) in a
//! form that compiles unchanged for userspace and for the XDP program.
//!
//! Everything is 32-bit add/rotate/xor or 32x32->64 multiplication on fixed-size
//! state: no tables, no data-dependent branches, no 128-bit arithmetic, and no
//! unbounded loops. Userspace uses the SIMD RustCrypto implementation for bulk
//! data; tests pin both implementations to the same RFC vectors.

/// 256-bit key as eight little-endian words.
pub type Key = [u32; 8];

pub const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[inline(always)]
fn quarter(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

/// The 20-round ChaCha permutation, without the final feed-forward addition.
#[inline(always)]
pub fn permute(state: &mut [u32; 16]) {
    // A local copy lets LLVM keep words in registers instead of memory.
    let mut x = *state;
    for _ in 0..10 {
        quarter(&mut x, 0, 4, 8, 12);
        quarter(&mut x, 1, 5, 9, 13);
        quarter(&mut x, 2, 6, 10, 14);
        quarter(&mut x, 3, 7, 11, 15);
        quarter(&mut x, 0, 5, 10, 15);
        quarter(&mut x, 1, 6, 11, 12);
        quarter(&mut x, 2, 7, 8, 13);
        quarter(&mut x, 3, 4, 9, 14);
    }
    *state = x;
}

/// Initial state for block `counter` with a 96-bit nonce (RFC 8439 section 2.3).
#[inline(always)]
pub fn state(key: &Key, counter: u32, nonce: &[u32; 3]) -> [u32; 16] {
    [
        SIGMA[0], SIGMA[1], SIGMA[2], SIGMA[3], key[0], key[1], key[2], key[3], key[4], key[5],
        key[6], key[7], counter, nonce[0], nonce[1], nonce[2],
    ]
}

/// Add the input state back after [`permute`], producing one keystream block.
#[inline(always)]
pub fn feed_forward(output: &mut [u32; 16], input: &[u32; 16]) {
    for (o, i) in output.iter_mut().zip(input) {
        *o = o.wrapping_add(*i);
    }
}

/// [`feed_forward`] without a saved copy of the input (saves BPF stack).
#[inline(always)]
pub fn add_state(output: &mut [u32; 16], key: &Key, counter: u32, nonce: &[u32; 3]) {
    for i in 0..4 {
        output[i] = output[i].wrapping_add(SIGMA[i]);
    }
    for i in 0..8 {
        output[4 + i] = output[4 + i].wrapping_add(key[i]);
    }
    output[12] = output[12].wrapping_add(counter);
    for i in 0..3 {
        output[13 + i] = output[13 + i].wrapping_add(nonce[i]);
    }
}

/// One 64-byte ChaCha20 keystream block as sixteen little-endian words.
#[inline(always)]
pub fn block(key: &Key, counter: u32, nonce: &[u32; 3]) -> [u32; 16] {
    let input = state(key, counter, nonce);
    let mut output = input;
    permute(&mut output);
    feed_forward(&mut output, &input);
    output
}

/// HChaCha20: a PRF from a 256-bit key and 128-bit input to a 256-bit key.
#[inline(always)]
pub fn hchacha(key: &Key, input: &[u32; 4]) -> Key {
    let mut x = hchacha_state(key, input);
    permute(&mut x);
    hchacha_output(&x)
}

#[inline(always)]
pub fn hchacha_state(key: &Key, input: &[u32; 4]) -> [u32; 16] {
    let mut x = state(key, input[0], &[input[1], input[2], input[3]]);
    x[12] = input[0];
    x
}

#[inline(always)]
pub fn hchacha_output(x: &[u32; 16]) -> Key {
    [x[0], x[1], x[2], x[3], x[12], x[13], x[14], x[15]]
}

/// The 96-bit AEAD nonce: a direction word followed by the 64-bit counter.
#[inline(always)]
pub const fn nonce(direction: u32, counter: u64) -> [u32; 3] {
    [direction, counter as u32, (counter >> 32) as u32]
}

pub fn key_words(bytes: &[u8; 32]) -> Key {
    core::array::from_fn(|i| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()))
}

pub fn key_bytes(key: &Key) -> [u8; 32] {
    let mut out = [0; 32];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(key) {
        *chunk = word.to_le_bytes();
    }
    out
}

const MASK26: u32 = 0x03ff_ffff;

/// Poly1305 with five 26-bit limbs ("donna-32"). The eBPF instruction set has
/// 64-bit multiplication but no high-half multiply, which rules out 64-bit limbs.
#[derive(Clone, Copy)]
pub struct Poly1305 {
    r: [u32; 5],
    s: [u32; 4],
    h: [u32; 5],
    pad: [u32; 4],
}

impl Poly1305 {
    /// `key` is the one-time key: r (clamped here) followed by s.
    #[inline(always)]
    pub fn new(key: &[u32; 8]) -> Self {
        let r = [
            key[0] & MASK26,
            ((key[0] >> 26) | (key[1] << 6)) & 0x03ff_ff03,
            ((key[1] >> 20) | (key[2] << 12)) & 0x03ff_c0ff,
            ((key[2] >> 14) | (key[3] << 18)) & 0x03f0_3fff,
            (key[3] >> 8) & 0x000f_ffff,
        ];
        Self {
            r,
            s: [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5],
            h: [0; 5],
            pad: [key[4], key[5], key[6], key[7]],
        }
    }

    /// One-time key for an AEAD message: the first half of ChaCha20 block 0.
    #[inline(always)]
    pub fn for_message(key: &Key, nonce: &[u32; 3]) -> Self {
        let b = block(key, 0, nonce);
        Self::new(&[b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }

    /// Absorb one full 16-byte block. In the AEAD construction every block is
    /// full: AAD and ciphertext are zero-padded to 16 bytes.
    #[inline(always)]
    pub fn block(&mut self, m: [u32; 4]) {
        let [r0, r1, r2, r3, r4] = self.r.map(u64::from);
        let [s1, s2, s3, s4] = self.s.map(u64::from);
        let h0 = (self.h[0] + (m[0] & MASK26)) as u64;
        let h1 = (self.h[1] + (((m[0] >> 26) | (m[1] << 6)) & MASK26)) as u64;
        let h2 = (self.h[2] + (((m[1] >> 20) | (m[2] << 12)) & MASK26)) as u64;
        let h3 = (self.h[3] + (((m[2] >> 14) | (m[3] << 18)) & MASK26)) as u64;
        let h4 = (self.h[4] + ((m[3] >> 8) | (1 << 24))) as u64;

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        d1 += d0 >> 26;
        d2 += d1 >> 26;
        d3 += d2 >> 26;
        d4 += d3 >> 26;
        let mut h0 = (d0 as u32 & MASK26) + (d4 >> 26) as u32 * 5;
        let h1 = (d1 as u32 & MASK26) + (h0 >> 26);
        h0 &= MASK26;
        self.h = [
            h0,
            h1,
            d2 as u32 & MASK26,
            d3 as u32 & MASK26,
            d4 as u32 & MASK26,
        ];
    }

    #[inline(always)]
    pub fn finish(self) -> [u32; 4] {
        let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h;
        let mut c = h1 >> 26;
        h1 &= MASK26;
        h2 += c;
        c = h2 >> 26;
        h2 &= MASK26;
        h3 += c;
        c = h3 >> 26;
        h3 &= MASK26;
        h4 += c;
        c = h4 >> 26;
        h4 &= MASK26;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= MASK26;
        h1 += c;

        // g = h + 5 - 2^130; keep h when that subtraction underflows.
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= MASK26;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= MASK26;
        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= MASK26;
        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= MASK26;
        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);
        let select = (g4 >> 31).wrapping_sub(1);
        let keep = !select;
        h0 = (h0 & keep) | (g0 & select);
        h1 = (h1 & keep) | (g1 & select);
        h2 = (h2 & keep) | (g2 & select);
        h3 = (h3 & keep) | (g3 & select);
        h4 = (h4 & keep) | (g4 & select);

        let words = [
            h0 | (h1 << 26),
            (h1 >> 6) | (h2 << 20),
            (h2 >> 12) | (h3 << 14),
            (h3 >> 18) | (h4 << 8),
        ];
        let mut tag = [0; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            carry += words[i] as u64 + self.pad[i] as u64;
            tag[i] = carry as u32;
            carry >>= 32;
        }
        tag
    }
}

/// Split two little-endian 64-bit loads into Poly1305 message words.
#[inline(always)]
pub const fn words(a: u64, b: u64) -> [u32; 4] {
    [a as u32, (a >> 32) as u32, b as u32, (b >> 32) as u32]
}

/// Final AEAD block: little-endian 64-bit AAD and ciphertext lengths.
#[inline(always)]
pub const fn lengths(aad: u32, ciphertext: u32) -> [u32; 4] {
    [aad, 0, ciphertext, 0]
}

/// Compare tags without an early exit.
#[inline(always)]
pub fn tags_equal(a: &[u32; 4], b: &[u32; 4]) -> bool {
    ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3])) == 0
}

/// Replay windows are rings of 64-bit slots updated with one compare-exchange:
/// the high 48 bits name a block of 16 counters and the low 16 bits mark the
/// counters seen in it. A slot only moves to newer blocks, so a counter is
/// accepted at most once even when CPUs race. Counters must be below 2^52.
pub const REPLAY_BITS: u32 = 16;

#[inline(always)]
pub const fn replay_index(counter: u64, slots: usize) -> usize {
    ((counter >> REPLAY_BITS.trailing_zeros()) as usize) % slots
}

/// The slot's next value if `counter` is new, `None` if it was seen or is older
/// than the window.
#[inline(always)]
pub const fn replay_update(slot: u64, counter: u64) -> Option<u64> {
    let block = counter >> REPLAY_BITS.trailing_zeros();
    let bit = 1u64 << (counter & (REPLAY_BITS as u64 - 1));
    let current = slot >> REPLAY_BITS;
    if current == block {
        if slot & bit != 0 {
            None
        } else {
            Some(slot | bit)
        }
    } else if current < block {
        Some((block << REPLAY_BITS) | bit)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_to_words<const N: usize>(bytes: &[u8]) -> [u32; N] {
        core::array::from_fn(|i| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()))
    }

    #[test]
    fn rfc8439_block_2_3_2() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = bytes_to_words::<3>(&[0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0]);
        let out = block(&key_words(&key), 1, &nonce);
        let mut again = state(&key_words(&key), 1, &nonce);
        permute(&mut again);
        add_state(&mut again, &key_words(&key), 1, &nonce);
        assert_eq!(again, out);
        assert_eq!(
            out,
            [
                0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, 0xc7f4d1c7, 0x0368c033, 0x9aaa2204,
                0x4e6cd4c3, 0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9, 0xd19c12b5, 0xb94e16de,
                0xe883d0cb, 0x4e3c50a2,
            ]
        );
    }

    #[test]
    fn poly1305_final_reduction_edge_cases() {
        // r = 2 and a block of ones accumulate h = 2^130 - 2, i.e. 3 mod p.
        let mut key = [0u8; 32];
        key[0] = 2;
        let mut poly = Poly1305::new(&key_words(&key));
        let tag = raw_tail_block(&mut poly, &[0xff; 16]);
        assert_eq!(
            tag,
            bytes_to_words::<4>(&[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        );

        // h = 2^129 + 4 < p; adding s = 2^128 - 1 wraps modulo 2^128.
        let mut key = [0u8; 32];
        key[0] = 2;
        key[16..].fill(0xff);
        let mut poly = Poly1305::new(&key_words(&key));
        let mut m = [0u8; 16];
        m[0] = 2;
        let tag = raw_tail_block(&mut poly, &m);
        assert_eq!(
            tag,
            bytes_to_words::<4>(&[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        );
    }

    // A single full 16-byte block (2^128 bit set, as in the AEAD).
    fn raw_tail_block(poly: &mut Poly1305, m: &[u8; 16]) -> [u32; 4] {
        poly.block(bytes_to_words(m));
        poly.finish()
    }

    #[test]
    fn hchacha_draft_xchacha_2_2_1() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let input = bytes_to_words::<4>(&[
            0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0, 0x31, 0x41, 0x59, 0x27,
        ]);
        let out = key_bytes(&hchacha(&key_words(&key), &input));
        assert_eq!(
            out,
            [
                0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe, 0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87,
                0x7d, 0x73, 0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53, 0xc1, 0x2e, 0xc4, 0x13,
                0x26, 0xd3, 0xec, 0xdc,
            ]
        );
    }

    #[test]
    fn replay_window_accepts_each_counter_once() {
        let mut slots = [0u64; 4];
        let mut accept = |c: u64| {
            let i = replay_index(c, slots.len());
            match replay_update(slots[i], c) {
                Some(v) => {
                    slots[i] = v;
                    true
                }
                None => false,
            }
        };
        assert!(accept(1));
        assert!(!accept(1));
        assert!(accept(3));
        assert!(accept(2));
        assert!(accept(63)); // same ring as 1..15 is block 0; 63 is block 3
        assert!(accept(64)); // block 4 reuses slot 0
        assert!(!accept(5), "block 0 fell out of the window");
        assert!(accept(48), "block 3 is still inside the window");
        assert!(!accept(63));
        assert!(accept((1 << 48) - 1));
        assert!(!accept((1 << 48) - 1));
    }
}
