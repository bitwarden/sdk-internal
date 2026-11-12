//! TupleHash (NIST SP 800-185 §5).
//!
//! Hashes a sequence of byte strings unambiguously: `("ab", "c")` and `("a", "bc")` differ.

use crate::backend;

/// TupleHash256 of `items` with customization string `customization`, filling `out`.
pub fn tuple_hash256(items: &[&[u8]], customization: &[u8], out: &mut [u8]) {
    backend::tuple_hash::tuple_hash256(items, customization, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    const ITEMS: [&[u8]; 2] = [&[0x00, 0x01, 0x02], &[0x10, 0x11, 0x12, 0x13, 0x14, 0x15]];

    // NIST SP 800-185 TupleHash256 sample #4.
    #[test]
    fn known_answer_no_customization() {
        let mut out = [0u8; 64];
        tuple_hash256(&ITEMS, b"", &mut out);
        assert_eq!(
            hex::encode(out),
            "cfb7058caca5e668f81a12a20a2195ce97a925f1dba3e7449a56f82201ec6073\
             11ac2696b1ab5ea2352df1423bde7bd4bb78c9aed1a853c78672f9eb23bbe194"
        );
    }

    // NIST SP 800-185 TupleHash256 sample #5.
    #[test]
    fn known_answer_with_customization() {
        let mut out = [0u8; 64];
        tuple_hash256(&ITEMS, b"My Tuple App", &mut out);
        assert_eq!(
            hex::encode(out),
            "147c2191d5ed7efd98dbd96d7ab5a11692576f5fe2a5065f3e33de6bba9f3aa1\
             c4e9a068a289c61c95aab30aee1e410b0b607de3620e24a4e3bf9852a1d4367e"
        );
    }

    #[test]
    fn tuple_boundaries_matter() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        tuple_hash256(&[b"ab", b"c"], b"", &mut a);
        tuple_hash256(&[b"a", b"bc"], b"", &mut b);
        assert_ne!(a, b);
    }
}
