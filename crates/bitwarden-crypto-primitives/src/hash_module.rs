/// Generates a hash module body: `DIGEST_LEN`, one-shot `digest()`, an incremental hasher, and
/// tests against the FIPS 180 "abc" and empty-input known answers.
macro_rules! hash_module {
    ($hasher:ident, $len:expr, $abc_kat:expr, $empty_kat:expr) => {
        use crate::backend;

        /// Digest length in bytes.
        pub const DIGEST_LEN: usize = $len;

        /// Hashes `data` in one shot.
        pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
            let mut hasher = $hasher::new();
            hasher.update(data);
            hasher.finalize()
        }

        /// Incremental hasher.
        #[derive(Clone, Default)]
        pub struct $hasher(backend::digest::$hasher);

        impl $hasher {
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
                assert_eq!(hex::encode(digest(b"abc")), $abc_kat);
            }

            #[test]
            fn known_answer_empty() {
                assert_eq!(hex::encode(digest(b"")), $empty_kat);
            }

            #[test]
            fn incremental_matches_one_shot() {
                let mut hasher = $hasher::new();
                hasher.update(b"a");
                hasher.update(b"bc");
                assert_eq!(hasher.finalize(), digest(b"abc"));
            }
        }
    };
}
