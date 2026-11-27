//! Test vector helpers. Vectors are always written as hex strings and decoded here.

/// Decodes a hex test vector.
pub(crate) fn bytes(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("test vector is valid hex")
}

/// Decodes a hex test vector of a fixed length.
pub(crate) fn array<const N: usize>(hex_str: &str) -> [u8; N] {
    bytes(hex_str)
        .try_into()
        .expect("test vector has the expected length")
}
