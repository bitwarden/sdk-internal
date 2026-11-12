//! PBKDF2 (RFC 8018).

use std::num::NonZeroU32;

use crate::backend;

/// PBKDF2-HMAC-SHA256 of `password` and `salt` into `out`.
pub fn hmac_sha256(password: &[u8], salt: &[u8], rounds: NonZeroU32, out: &mut [u8]) {
    backend::pbkdf2::hmac_sha256(password, salt, rounds, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer() {
        // RFC 7914 §11 style vector for PBKDF2-HMAC-SHA256, c = 1.
        let mut out = [0u8; 32];
        hmac_sha256(b"password", b"salt", NonZeroU32::MIN, &mut out);
        assert_eq!(
            hex::encode(out),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }
}
