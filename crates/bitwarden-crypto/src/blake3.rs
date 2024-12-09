/**
 * A wrapper around blake3 that allows hashing multiple data chunks into one hash without
 * the risk of ambiguous message formats leading to colliding hashes.
 * https://blog.trailofbits.com/2024/08/21/yolo-is-not-a-valid-hash-construction/
 * https://github.com/BLAKE3-team/BLAKE3/issues/84#issuecomment-623544768
 */
pub fn hash_blake3_tuple(data_chunks: &[&[u8]]) -> [u8; 32] {
    let init_key = [0u8; 32];
    let mut hasher = blake3::Hasher::new_keyed(&init_key);
    for data in data_chunks {
        hasher.update(data);
        // ratchet the hash state
        hasher = blake3::Hasher::new_keyed(hasher.finalize().as_bytes());
    }
    let hash = hasher.finalize();
    *hash.as_bytes()
}
