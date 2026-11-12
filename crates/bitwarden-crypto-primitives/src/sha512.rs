//! SHA-512.

use crate::backend;

/// Digest length in bytes.
pub const DIGEST_LEN: usize = 64;

/// Hashes `data` in one shot.
pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize()
}

/// Incremental hasher.
#[derive(Clone, Default)]
pub struct Sha512(backend::digest::Sha512);

impl Sha512 {
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
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let mut hasher = Sha512::new();
        hasher.update(b"a");
        hasher.update(b"bc");
        assert_eq!(hasher.finalize(), digest(b"abc"));
    }
}
