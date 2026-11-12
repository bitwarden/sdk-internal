//! SHA-384.

use crate::backend;

/// Digest length in bytes.
pub const DIGEST_LEN: usize = 48;

/// Hashes `data` in one shot.
pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize()
}

/// Incremental hasher.
#[derive(Clone, Default)]
pub struct Sha384(backend::digest::Sha384);

impl Sha384 {
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
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let mut hasher = Sha384::new();
        hasher.update(b"a");
        hasher.update(b"bc");
        assert_eq!(hasher.finalize(), digest(b"abc"));
    }
}
