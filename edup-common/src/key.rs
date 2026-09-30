//! Long-term user key derivation from the configured password (userspace only).

use blake2::{Blake2s256, Digest};

use crate::crypto::{self, Key};

/// A fast hash, not a password KDF: use generated passwords (`edup-client
/// credentials`). Captured handshakes allow offline guessing of weak ones.
pub fn derive_key(password: &str) -> Key {
    let mut h = Blake2s256::new();
    h.update(b"edup v5 user key\0");
    h.update(password.as_bytes());
    crypto::key_words(&h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_distinct() {
        assert_eq!(derive_key("a"), derive_key("a"));
        assert_ne!(derive_key("a"), derive_key("b"));
    }
}
