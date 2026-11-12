//! SHA-1. Legacy use only (TOTP, HIBP, RSA-OAEP-SHA1).

use crate::backend;

/// Digest length in bytes.
pub const DIGEST_LEN: usize = 20;

/// Hashes `data` in one shot.
pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize()
}

/// Incremental hasher.
#[derive(Clone, Default)]
pub struct Sha1(backend::digest::Sha1);

impl Sha1 {
    /// Creates an empty hasher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorbs `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Returns the digest.
    pub fn finalize(self) -> [u8; DIGEST_LEN] {
        self.0.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer_abc() {
        assert_eq!(
            hex::encode(digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let mut hasher = Sha1::new();
        hasher.update(b"a");
        hasher.update(b"bc");
        assert_eq!(hasher.finalize(), digest(b"abc"));
    }
}
