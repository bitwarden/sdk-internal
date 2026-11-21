//! PBKDF2 (RFC 8018).

use std::num::NonZeroU32;

use crate::backend;

/// PBKDF2-HMAC-SHA256 of `password` and `salt` into `out`.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], rounds: NonZeroU32, out: &mut [u8]) {
    backend::pbkdf2::pbkdf2_hmac_sha256(password, salt, rounds, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn derive(password: &[u8], salt: &[u8], rounds: u32, len: usize) -> String {
        let mut out = vec![0u8; len];
        let rounds = NonZeroU32::new(rounds).expect("non-zero rounds");
        pbkdf2_hmac_sha256(password, salt, rounds, &mut out);
        hex::encode(out)
    }

    /// RFC 7914 §11: two output blocks.
    #[test]
    fn known_answer() {
        assert_eq!(
            derive(b"passwd", b"salt", 1, 64),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
            49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        );
    }

    #[test]
    fn known_answer_empty_password_and_salt() {
        assert_eq!(
            derive(b"", b"salt", 2, 32),
            "62384466264daadc4144018c6bd864648272b34da8980d31521ffcce92ae003b"
        );
        assert_eq!(
            derive(b"password", b"", 2, 32),
            "8bc2f9167a81cdcfad1235cd9047f1136271c1f978fcfcb35e22dbeafa4634f6"
        );
    }

    /// Output one byte past a whole block, and a realistic iteration count.
    #[test]
    fn known_answer_partial_block_and_many_rounds() {
        assert_eq!(
            derive(b"password", b"salt", 2, 33),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43\
            83"
        );
        assert_eq!(
            derive(b"password", b"salt", 100_000, 32),
            "0394a2ede332c9a13eb82e9b24631604c31df978b4e2f0fbd2c549944f9d79a5"
        );
    }
}
