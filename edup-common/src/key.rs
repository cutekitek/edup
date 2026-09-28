//! Вывод ключа обфускации из пароля (только userspace).

use blake2::{Blake2s256, Digest};

use crate::wire::Key;

pub fn derive_key(password: &str) -> Key {
    let mut h = Blake2s256::new();
    h.update(b"edup v4 obfuscation key\0");
    h.update(password.as_bytes());
    let out = h.finalize();
    let word = |i: usize| u64::from_le_bytes(out[i..i + 8].try_into().unwrap());
    Key {
        k0: word(0),
        k1: word(8),
    }
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
