//! Userspace sealing, opening and handshake messages: RFC 8439
//! ChaCha20-Poly1305 from RustCrypto's SIMD ChaCha20 and the Poly1305 in
//! [`crate::crypto`], which the XDP program also uses. (RustCrypto's own
//! Poly1305 key setup costs ~0.7 µs per packet in portable x86-64 builds.)
//!
//! Handshake (one round trip, symmetric keys only):
//! - INIT carries a random client nonce `c`. It is authenticated with
//!   `K1 = HChaCha20(user_key, c)`, so a replay can only produce a new pending
//!   session on the server, never touch the active one.
//! - RESPONSE carries a server nonce `s` that is unique per handshake and per
//!   server load. The session key is `HChaCha20(K1, s)`; RESPONSE is sealed
//!   with it, which proves the server knows the user key and saw `c`.
//! - The server switches to the new session only after a packet sealed with
//!   it arrives, so replayed INITs cannot disrupt an established session.
use crate::{
    crypto::{self, Key, Poly1305},
    wire::{self, AAD_LEN, HANDSHAKE_LEN, HDR_LEN, Header, TAG_LEN},
};
use chacha20::{ChaCha20, KeyIvInit, cipher::StreamCipher};

pub struct Cipher {
    key: chacha20::Key,
}

fn nonce(direction: u32, counter: u64) -> chacha20::Nonce {
    let mut bytes = [0; 12];
    bytes[..4].copy_from_slice(&direction.to_le_bytes());
    bytes[4..].copy_from_slice(&counter.to_le_bytes());
    bytes.into()
}

/// Absorb `data` zero-padded to whole 16-byte blocks.
fn absorb(poly: &mut Poly1305, data: &[u8]) {
    let (blocks, tail) = data.as_chunks::<16>();
    for block in blocks {
        let (a, b) = block.split_at(8);
        poly.block(crypto::words(
            u64::from_le_bytes(a.try_into().unwrap()),
            u64::from_le_bytes(b.try_into().unwrap()),
        ));
    }
    if !tail.is_empty() {
        let mut block = [0; 16];
        block[..tail.len()].copy_from_slice(tail);
        absorb(poly, &block);
    }
}

fn tag_bytes(words: [u32; 4]) -> [u8; TAG_LEN] {
    let mut tag = [0; TAG_LEN];
    for (chunk, word) in tag.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        *chunk = word.to_le_bytes();
    }
    tag
}

fn tag_words(tag: &[u8]) -> [u32; 4] {
    core::array::from_fn(|i| u32::from_le_bytes(tag[i * 4..i * 4 + 4].try_into().unwrap()))
}

impl Cipher {
    pub fn new(key: &Key) -> Self {
        Self {
            key: crypto::key_bytes(key).into(),
        }
    }

    /// ChaCha20 positioned at block 1 and the Poly1305 state keyed from
    /// block 0 (RFC 8439 section 2.8).
    fn start(&self, direction: u32, counter: u64) -> (ChaCha20, Poly1305) {
        let mut stream = ChaCha20::new(&self.key, &nonce(direction, counter));
        let mut block = [0; 64];
        stream.apply_keystream(&mut block);
        let key = crypto::key_words(block[..32].try_into().unwrap());
        (stream, Poly1305::new(&key))
    }

    fn tag(mut poly: Poly1305, aad: &[u8], ciphertext: &[u8]) -> [u32; 4] {
        absorb(&mut poly, aad);
        absorb(&mut poly, ciphertext);
        poly.block(crypto::lengths(aad.len() as u32, ciphertext.len() as u32));
        poly.finish()
    }

    /// Encrypts `pkt[HDR_LEN..]` in place and writes the tag. The encoded
    /// header must already be in `pkt[..AAD_LEN]`; its counter is the nonce.
    pub fn seal(&self, direction: u32, pkt: &mut [u8]) {
        let mut counter = [0; 8];
        counter[2..].copy_from_slice(&pkt[10..AAD_LEN]);
        let (head, body) = pkt.split_at_mut(HDR_LEN);
        let (mut stream, poly) = self.start(direction, u64::from_be_bytes(counter));
        stream.apply_keystream(body);
        let tag = Self::tag(poly, &head[..AAD_LEN], body);
        head[AAD_LEN..].copy_from_slice(&tag_bytes(tag));
    }

    /// Verifies, then decrypts in place. Rejected packets stay encrypted.
    pub fn open(&self, direction: u32, pkt: &mut [u8]) -> Option<Header> {
        let header = Header::decode(pkt)?;
        if pkt.len() < HDR_LEN || header.typ >= wire::TYPE_INIT {
            return None;
        }
        let (head, body) = pkt.split_at_mut(HDR_LEN);
        let (mut stream, poly) = self.start(direction, header.counter);
        let tag = Self::tag(poly, &head[..AAD_LEN], body);
        if !crypto::tags_equal(&tag, &tag_words(&head[AAD_LEN..])) {
            return None;
        }
        stream.apply_keystream(body);
        Some(header)
    }

    /// Tag of a message with no ciphertext.
    fn mac(&self, direction: u32, aad: &[u8]) -> [u32; 4] {
        let (_, poly) = self.start(direction, 0);
        Self::tag(poly, aad, &[])
    }
}

/// Compact and seal an IP packet already placed at `pkt[HDR_LEN..]`.
/// Returns the datagram length.
pub fn seal_data(
    cipher: &Cipher,
    user: i64,
    phase: u8,
    counter: u64,
    pkt: &mut [u8],
    to_server: bool,
) -> Option<usize> {
    let (typ, len) = wire::compact(pkt, to_server)?;
    let header = Header {
        user,
        typ,
        phase,
        counter,
    };
    pkt[..AAD_LEN].copy_from_slice(&header.encode());
    let direction = if to_server {
        wire::TO_SERVER
    } else {
        wire::TO_CLIENT
    };
    cipher.seal(direction, &mut pkt[..len]);
    Some(len)
}

pub fn keepalive(cipher: &Cipher, header: Header, direction: u32) -> [u8; HDR_LEN] {
    let mut pkt = [0; HDR_LEN];
    pkt[..AAD_LEN].copy_from_slice(
        &Header {
            typ: wire::TYPE_KEEPALIVE,
            ..header
        }
        .encode(),
    );
    cipher.seal(direction, &mut pkt);
    pkt
}

fn nonce_words(nonce: &[u8; wire::NONCE_LEN]) -> [u32; 4] {
    core::array::from_fn(|i| u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap()))
}

/// K1 = HChaCha20(user key, client nonce): authenticates INIT.
pub fn init_key(user_key: &Key, client_nonce: &[u8; wire::NONCE_LEN]) -> Key {
    crypto::hchacha(user_key, &nonce_words(client_nonce))
}

/// Session key = HChaCha20(K1, server nonce).
pub fn session_key(init_key: &Key, server_nonce: &[u8; wire::NONCE_LEN]) -> Key {
    crypto::hchacha(init_key, &nonce_words(server_nonce))
}

// Handshake packets have no ciphertext: header and nonce are associated data.
fn handshake_aad(pkt: &[u8; HANDSHAKE_LEN]) -> [u8; AAD_LEN + wire::NONCE_LEN] {
    let mut aad = [0; AAD_LEN + wire::NONCE_LEN];
    aad[..AAD_LEN].copy_from_slice(&pkt[..AAD_LEN]);
    aad[AAD_LEN..].copy_from_slice(&pkt[HDR_LEN..]);
    aad
}

fn handshake_seal(key: &Key, direction: u32, pkt: &mut [u8; HANDSHAKE_LEN]) {
    let tag = Cipher::new(key).mac(direction, &handshake_aad(pkt));
    pkt[AAD_LEN..HDR_LEN].copy_from_slice(&tag_bytes(tag));
}

fn handshake_verify(key: &Key, direction: u32, pkt: &[u8; HANDSHAKE_LEN]) -> bool {
    let tag = Cipher::new(key).mac(direction, &handshake_aad(pkt));
    crypto::tags_equal(&tag, &tag_words(&pkt[AAD_LEN..HDR_LEN]))
}

fn handshake_packet(
    user: i64,
    typ: u8,
    phase: u8,
    nonce: &[u8; wire::NONCE_LEN],
) -> [u8; HANDSHAKE_LEN] {
    let mut pkt = [0; HANDSHAKE_LEN];
    pkt[..AAD_LEN].copy_from_slice(
        &Header {
            user,
            typ,
            phase,
            counter: 0,
        }
        .encode(),
    );
    pkt[HDR_LEN..].copy_from_slice(nonce);
    pkt
}

/// Client: build INIT for a fresh random `client_nonce`. Returns K1, which is
/// needed to accept the matching RESPONSE.
pub fn init(
    user_key: &Key,
    user: i64,
    client_nonce: &[u8; wire::NONCE_LEN],
) -> ([u8; HANDSHAKE_LEN], Key) {
    let k1 = init_key(user_key, client_nonce);
    let mut pkt = handshake_packet(user, wire::TYPE_INIT, 0, client_nonce);
    handshake_seal(&k1, wire::TO_SERVER, &mut pkt);
    (pkt, k1)
}

/// Server reference (the XDP program implements this): verify INIT, return K1.
pub fn open_init(user_key: &Key, pkt: &[u8]) -> Option<Key> {
    let pkt: &[u8; HANDSHAKE_LEN] = pkt.try_into().ok()?;
    let header = Header::decode(pkt)?;
    if header.typ != wire::TYPE_INIT || header.phase != 0 || header.counter != 0 {
        return None;
    }
    let k1 = init_key(user_key, pkt[HDR_LEN..].try_into().unwrap());
    handshake_verify(&k1, wire::TO_SERVER, pkt).then_some(k1)
}

/// Server reference: RESPONSE for session `phase`; returns the session key.
pub fn response(
    init_key: &Key,
    user: i64,
    phase: u8,
    server_nonce: &[u8; wire::NONCE_LEN],
) -> ([u8; HANDSHAKE_LEN], Key) {
    let key = session_key(init_key, server_nonce);
    let mut pkt = handshake_packet(user, wire::TYPE_RESPONSE, phase, server_nonce);
    handshake_seal(&key, wire::TO_CLIENT, &mut pkt);
    (pkt, key)
}

/// Client: accept a RESPONSE to the INIT that produced `init_key`.
/// Returns the session key and its phase.
pub fn open_response(init_key: &Key, pkt: &[u8]) -> Option<(Key, u8)> {
    let pkt: &[u8; HANDSHAKE_LEN] = pkt.try_into().ok()?;
    let header = Header::decode(pkt)?;
    if header.typ != wire::TYPE_RESPONSE || header.counter != 0 {
        return None;
    }
    let key = session_key(init_key, pkt[HDR_LEN..].try_into().unwrap());
    handshake_verify(&key, wire::TO_CLIENT, pkt).then_some((key, header.phase))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit, XChaCha20Poly1305};
    use std::vec::Vec;

    const KEY: Key = [
        0x0302_0100,
        0x0706_0504,
        0x0b0a_0908,
        0x0f0e_0d0c,
        0x1312_1110,
        0x1716_1514,
        0x1b1a_1918,
        0x1f1e_1d1c,
    ];

    // The portable construction, as the XDP program applies it to a packet.
    fn portable_seal(key: &Key, direction: u32, pkt: &mut [u8]) {
        let header = Header::decode(pkt).unwrap();
        let n = crypto::nonce(direction, header.counter);
        let mut poly = Poly1305::for_message(key, &n);
        let word = |b: &[u8]| {
            let mut padded = [0; 16];
            padded[..b.len()].copy_from_slice(b);
            core::array::from_fn(|i| {
                u32::from_le_bytes(padded[i * 4..i * 4 + 4].try_into().unwrap())
            })
        };
        poly.block(word(&pkt[..AAD_LEN]));
        let len = pkt.len() - HDR_LEN;
        for (i, chunk) in pkt[HDR_LEN..].chunks_mut(64).enumerate() {
            let ks = crypto::block(key, i as u32 + 1, &n);
            for (j, b) in chunk.iter_mut().enumerate() {
                *b ^= (ks[j / 4] >> (8 * (j % 4))) as u8;
            }
            for unit in chunk.chunks(16) {
                poly.block(word(unit));
            }
        }
        poly.block(crypto::lengths(AAD_LEN as u32, len as u32));
        let tag = poly.finish();
        for (i, w) in tag.iter().enumerate() {
            pkt[AAD_LEN + i * 4..AAD_LEN + i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
    }

    fn packet(len: usize, counter: u64) -> Vec<u8> {
        let mut pkt: Vec<u8> = (0..HDR_LEN + len).map(|i| (i * 31 + 7) as u8).collect();
        pkt[..AAD_LEN].copy_from_slice(
            &Header {
                user: -42,
                typ: wire::TYPE_DATA,
                phase: 1,
                counter,
            }
            .encode(),
        );
        pkt
    }

    // The reference: RustCrypto's complete ChaCha20-Poly1305.
    fn reference_seal(key: &Key, direction: u32, pkt: &mut [u8]) {
        let header = Header::decode(pkt).unwrap();
        let (head, body) = pkt.split_at_mut(HDR_LEN);
        let nonce: [u8; 12] = nonce(direction, header.counter).into();
        let tag = ChaCha20Poly1305::new(&crypto::key_bytes(key).into())
            .encrypt_inout_detached(&nonce.into(), &head[..AAD_LEN], body.into())
            .unwrap();
        head[AAD_LEN..].copy_from_slice(&tag);
    }

    #[test]
    fn seal_and_xdp_construction_match_rustcrypto_at_every_length() {
        for len in 0..=wire::MAX_BODY {
            for direction in [wire::TO_SERVER, wire::TO_CLIENT] {
                let counter = (len as u64) << 40 | 0x1234;
                let mut ours = packet(len, counter);
                let mut xdp = ours.clone();
                let mut reference = ours.clone();
                Cipher::new(&KEY).seal(direction, &mut ours);
                portable_seal(&KEY, direction, &mut xdp);
                reference_seal(&KEY, direction, &mut reference);
                assert_eq!(ours, reference, "len={len} direction={direction}");
                assert_eq!(xdp, reference, "len={len} direction={direction}");
                assert!(Cipher::new(&KEY).open(direction, &mut ours).is_some());
                assert_eq!(ours[HDR_LEN..], packet(len, counter)[HDR_LEN..]);
            }
        }
    }

    #[test]
    fn hchacha_matches_xchacha20poly1305_subkey() {
        // XChaCha20-Poly1305(K, n) = ChaCha20-Poly1305(HChaCha20(K, n[..16]), 0^4 || n[16..]).
        let xnonce: [u8; 24] = core::array::from_fn(|i| (i * 13 + 1) as u8);
        let aad = b"edup";
        let mut expected = *b"payload bytes";
        let tag = XChaCha20Poly1305::new(&crypto::key_bytes(&KEY).into())
            .encrypt_inout_detached(&xnonce.into(), aad, (&mut expected[..]).into())
            .unwrap();
        let subkey = init_key(&KEY, xnonce[..16].try_into().unwrap());
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&xnonce[16..]);
        let mut actual = *b"payload bytes";
        let actual_tag = ChaCha20Poly1305::new(&crypto::key_bytes(&subkey).into())
            .encrypt_inout_detached(&nonce.into(), aad, (&mut actual[..]).into())
            .unwrap();
        assert_eq!((actual, actual_tag), (expected, tag));
    }

    #[test]
    fn open_rejects_any_modification_wrong_key_and_direction() {
        let cipher = Cipher::new(&KEY);
        let mut sealed = packet(61, 9);
        cipher.seal(wire::TO_SERVER, &mut sealed);
        let mut ok = sealed.clone();
        assert_eq!(cipher.open(wire::TO_SERVER, &mut ok).unwrap().counter, 9);
        assert_eq!(&ok[HDR_LEN..], &packet(61, 9)[HDR_LEN..]);
        for byte in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[byte] ^= 0x10;
            assert!(
                cipher.open(wire::TO_SERVER, &mut bad).is_none(),
                "byte {byte}"
            );
        }
        assert!(cipher.open(wire::TO_CLIENT, &mut sealed.clone()).is_none());
        let mut other = KEY;
        other[7] ^= 1;
        assert!(
            Cipher::new(&other)
                .open(wire::TO_SERVER, &mut sealed.clone())
                .is_none()
        );
        assert!(
            cipher
                .open(wire::TO_SERVER, &mut sealed[..HDR_LEN - 1].to_vec())
                .is_none()
        );
    }

    #[test]
    fn handshake_derives_one_session_key_and_rejects_forgery() {
        let client_nonce = [7; 16];
        let (init_pkt, k1) = init(&KEY, 99, &client_nonce);
        assert_eq!(open_init(&KEY, &init_pkt), Some(k1));
        let mut other = KEY;
        other[0] ^= 1;
        assert!(open_init(&other, &init_pkt).is_none());
        for byte in 0..HANDSHAKE_LEN {
            let mut bad = init_pkt;
            bad[byte] ^= 1;
            assert!(open_init(&KEY, &bad).is_none(), "INIT byte {byte}");
        }
        let server_nonce = [9; 16];
        let (resp, key) = response(&k1, 99, 1, &server_nonce);
        assert_eq!(open_response(&k1, &resp), Some((key, 1)));
        assert_ne!(key, k1);
        // A response to a different INIT does not authenticate.
        let (_, k1_other) = init(&KEY, 99, &[8; 16]);
        assert!(open_response(&k1_other, &resp).is_none());
        for byte in 0..HANDSHAKE_LEN {
            let mut bad = resp;
            bad[byte] ^= 1;
            assert!(open_response(&k1, &bad).is_none(), "RESPONSE byte {byte}");
        }
        // Handshake packets are never accepted as data, and vice versa.
        assert!(
            Cipher::new(&key)
                .open(wire::TO_CLIENT, &mut resp.clone())
                .is_none()
        );
        let ka = keepalive(
            &Cipher::new(&key),
            Header {
                user: 99,
                typ: wire::TYPE_KEEPALIVE,
                phase: 1,
                counter: 1,
            },
            wire::TO_CLIENT,
        );
        let mut padded = [0; HANDSHAKE_LEN];
        padded[..HDR_LEN].copy_from_slice(&ka);
        assert!(open_response(&k1, &padded).is_none());
    }
}
