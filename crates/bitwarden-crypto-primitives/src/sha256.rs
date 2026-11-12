//! SHA-256.

use crate::backend;

/// Digest length in bytes.
pub const DIGEST_LEN: usize = 32;

/// Hashes `data` in one shot.
pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// Incremental hasher.
#[derive(Clone, Default)]
pub struct Sha256(backend::digest::Sha256);

impl Sha256 {
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
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let mut hasher = Sha256::new();
        hasher.update(b"a");
        hasher.update(b"bc");
        assert_eq!(hasher.finalize(), digest(b"abc"));
    }
}
