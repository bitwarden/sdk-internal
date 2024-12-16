/**
 * A wrapper around blake3 that allows hashing multiple data chunks into one hash without
 * the risk of ambiguous message formats leading to colliding hashes.
 * https://blog.trailofbits.com/2024/08/21/yolo-is-not-a-valid-hash-construction/
 * https://github.com/BLAKE3-team/BLAKE3/issues/84#issuecomment-623544768
 */
pub fn hash_blake3_tuple(data_chunks: &[&[u8]]) -> [u8; 32] {
    let mut init_key = [0u8; 32];
    init_key.copy_from_slice(b"hash_blake3_tuple_init_key_bytes");
    let mut inner_state = blake3::Hasher::new_keyed(&init_key);
    for data in data_chunks {
        inner_state.update(data);
        // ratchet the hash state
        inner_state = blake3::Hasher::new_keyed(inner_state.finalize().as_bytes());
    }
    let final_inner_state = inner_state.finalize();

    // avoid leaking the internal state of hash_blake3_tuple
    // because otherwise preimage attacks could be possible
    blake3::hash(final_inner_state.as_bytes()).into()
}
