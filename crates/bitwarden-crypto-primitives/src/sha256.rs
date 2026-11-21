//! SHA-256.

hash_module!(
    Sha256,
    32,
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
);

#[cfg(test)]
mod vectors {
    use super::*;

    /// FIPS 180-2 long message: one million `a`, spanning many blocks.
    #[test]
    fn known_answer_million_a() {
        let digest = digest("a".repeat(1_000_000).as_bytes());
        assert_eq!(
            hex::encode(digest),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }
}
