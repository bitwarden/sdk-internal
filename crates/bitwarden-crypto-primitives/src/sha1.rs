//! SHA-1. Legacy use only (TOTP, HIBP, RSA-OAEP-SHA1).

hash_module!(
    Sha1,
    20,
    "a9993e364706816aba3e25717850c26c9cd0d89d",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709"
);

#[cfg(test)]
mod vectors {
    use super::*;

    #[test]
    fn known_answer_fox() {
        let digest = digest(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            hex::encode(digest),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }
}
