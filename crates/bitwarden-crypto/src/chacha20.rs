use chacha20::{
    cipher::{NewCipher, StreamCipher},
    XChaCha20,
};
use chacha20poly1305::{AeadCore, AeadInPlace, KeyInit, XChaCha20Poly1305};
use generic_array::GenericArray;
use poly1305::{universal_hash::UniversalHash, Poly1305};
use subtle::ConstantTimeEq;

/**
 * Note:
 * XChaCha20Poly1305 encrypts data, and authenticates associated data using
 * XChaCha20Poly1305 Specifically, this uses the CTX construction, proposed here: https://par.nsf.gov/servlets/purl/10391723
 * using blake3 as the cryptographic hash function. The entire construction is called
 * XChaCha20Poly1305Blake3CTX. This provides not only key-commitment, but full-commitment.
 * In total, this scheme prevents attacks such as invisible salamanders.
 */
use crate::CryptoError;

pub struct XChaCha20Poly1305Blake3CTXCiphertext {
    nonce: [u8; 24],
    tag: [u8; 32],
    encrypted_data: Vec<u8>,
    authenticated_data: Vec<u8>,
}

pub fn encrypt_xchacha20_poly1305_blake3_ctx(
    key: &[u8; 32],
    plaintext_secret_data: &[u8],
    authenticated_data: &[u8],
) -> Result<XChaCha20Poly1305Blake3CTXCiphertext, CryptoError> {
    encrypt_xchacha20_poly1305_blake3_ctx_internal(
        rand::thread_rng(),
        key,
        plaintext_secret_data,
        authenticated_data,
    )
}

fn encrypt_xchacha20_poly1305_blake3_ctx_internal(
    rng: impl rand::CryptoRng + rand::RngCore,
    key: &[u8; 32],
    plaintext_secret_data: &[u8],
    associated_data: &[u8],
) -> Result<XChaCha20Poly1305Blake3CTXCiphertext, CryptoError> {
    let nonce = XChaCha20Poly1305::generate_nonce(rng);
    // This should never fail because XChaCha20Poly1305::generate_nonce always returns 24 bytes
    let nonce_slice: [u8; 24] = nonce.as_slice().try_into().expect("Nonce is 24 bytes");

    // This buffer contains the plaintext, that will be encrypted in-place
    let mut buffer = Vec::from(plaintext_secret_data);
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(key));

    let poly1305_tag = cipher
        .encrypt_in_place_detached(&nonce, associated_data, &mut buffer)
        .map_err(|_| CryptoError::InvalidKey)?;
    // This should never fail because poly1305_tag is always 16 bytes
    let poly1305_tag: [u8; 16] = poly1305_tag
        .as_slice()
        .try_into()
        .expect("A poly1305 tag is 16 bytes");

    Ok(XChaCha20Poly1305Blake3CTXCiphertext {
        nonce: nonce_slice,
        encrypted_data: buffer,
        authenticated_data: associated_data.to_vec(),
        tag: ctx_hash(key, &nonce_slice, associated_data, &poly1305_tag),
    })
}

pub fn decrypt_xchacha20_poly1305_blake3_ctx(
    key: &[u8; 32],
    ciphertext: &XChaCha20Poly1305Blake3CTXCiphertext,
) -> Result<Vec<u8>, CryptoError> {
    let buffer = ciphertext.encrypted_data.clone();
    let associated_data = ciphertext.authenticated_data.as_slice();

    // First, get the original polynomial tag, since this is required to calculate the ctx_tag
    let poly1305_tag = get_tag_expected_for_xchacha20_poly1305_ctx(
        key,
        &ciphertext.nonce,
        associated_data,
        &buffer,
    );
    // This should never fail because poly1305_tag is always 16 bytes
    let poly1305_tag_slice: [u8; 16] = poly1305_tag
        .as_slice()
        .try_into()
        .expect("A poly1305 tag is 16 bytes");
    let ctx_tag = ctx_hash(key, &ciphertext.nonce, associated_data, &poly1305_tag_slice);

    if ctx_tag.ct_eq(&ciphertext.tag).into() {
        // At this point the commitment is verified, so we can decrypt the data using regular
        // XChaCha20Poly1305
        let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(key));
        let mut buffer = ciphertext.encrypted_data.clone();
        let nonce_array = GenericArray::from_slice(&ciphertext.nonce);
        cipher
            .decrypt_in_place_detached(nonce_array, associated_data, &mut buffer, &poly1305_tag)
            .map_err(|_| CryptoError::InvalidKey)?;
        return Ok(buffer);
    }

    Err(CryptoError::InvalidKey)
}

/// The ctx hash function creates a cryptographic hash that binds to:
/// - The key
/// - The nonce
/// - The associated data
/// - The Poly1305 tag
/// - And by injectivity, also to the ciphertext.
///
/// Returns a 32 byte (256 bits) output hash, to give 128 bits of birthday-bound
/// context-comitting security (https://eprint.iacr.org/2024/875.pdf)
fn ctx_hash(
    key: &[u8; 32],
    nonce: &[u8; 24],
    associated_data: &[u8],
    poly1305_tag: &[u8; 16],
) -> [u8; 32] {
    // A cryptographic hash of the AD makes it fixed length
    let ad_hash = blake3::hash(associated_data);

    // It is safe to do a hash of the concatenations of the input values because all input values
    // have a fixed size and thus there can be no ambiguity about a pre-image having different
    // meanings, and leading to the same hash.
    //
    // T* = H(K, N, A, T)
    let ctx: &mut [u8; 32 * 2 + 24 + 16] = &mut [0u8; 32 * 2 + 24 + 16];
    ctx[..32].copy_from_slice(key);
    ctx[32..56].copy_from_slice(nonce);
    ctx[56..88].copy_from_slice(ad_hash.as_bytes());
    ctx[88..].copy_from_slice(poly1305_tag);
    let hash = blake3::hash(ctx.as_slice());
    *hash.as_bytes()
}

// This function copies internal behavior from the AEAD implementation in RustCrypto
fn get_tag_expected_for_xchacha20_poly1305_ctx(
    key: &[u8; 32],
    nonce: &[u8; 24],
    associated_data: &[u8],
    buffer: &[u8],
) -> chacha20poly1305::Tag {
    let mut xchacha20 = XChaCha20::new(
        GenericArray::from_slice(key),
        GenericArray::from_slice(nonce),
    );
    // https://github.com/RustCrypto/AEADs/blob/8403768230657812016e1b3d17b1638e5fdf5f73/chacha20poly1305/src/cipher.rs#L35-L37
    let mut mac_key = poly1305::Key::default();
    xchacha20.apply_keystream(&mut mac_key);

    // https://github.com/RustCrypto/AEADs/blob/8403768230657812016e1b3d17b1638e5fdf5f73/chacha20poly1305/src/cipher.rs#L85-L87
    let mut mac = Poly1305::new(GenericArray::from_slice(&mac_key));
    mac.update_padded(associated_data);
    mac.update_padded(buffer);
    authenticate_lengths(associated_data, buffer, &mut mac);
    mac.finalize()
}

/// This function copies internal behavior from the AEAD implementation in RustCrypto
/// https://github.com/RustCrypto/AEADs/blob/8403768230657812016e1b3d17b1638e5fdf5f73/chacha20poly1305/src/cipher.rs#L100-L111
fn authenticate_lengths(associated_data: &[u8], buffer: &[u8], mac: &mut Poly1305) {
    let associated_data_len: u64 = associated_data.len() as u64;
    let buffer_len: u64 = buffer.len() as u64;

    let mut block = GenericArray::default();
    block[..8].copy_from_slice(&associated_data_len.to_le_bytes());
    block[8..].copy_from_slice(&buffer_len.to_le_bytes());
    mac.update(&[block]);
}

mod tests {
    #[cfg(test)]
    use crate::chacha20::*;

    #[test]
    fn test_encrypt_decrypt_xchacha20_poly1305_ctx() {
        let key = [0u8; 32];
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";

        let encrypted =
            encrypt_xchacha20_poly1305_blake3_ctx(&key, plaintext_secret_data, authenticated_data)
                .unwrap();
        let decrypted = decrypt_xchacha20_poly1305_blake3_ctx(&key, &encrypted).unwrap();
        assert_eq!(plaintext_secret_data, decrypted.as_slice());
    }

    #[test]
    fn test_fails_when_ciphertext_changed() {
        let key = [0u8; 32];
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";

        let mut encrypted =
            encrypt_xchacha20_poly1305_blake3_ctx(&key, plaintext_secret_data, authenticated_data)
                .unwrap();
        encrypted.encrypted_data[0] = encrypted.encrypted_data[0].wrapping_add(1);
        let result = decrypt_xchacha20_poly1305_blake3_ctx(&key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_fails_when_associated_data_changed() {
        let key = [0u8; 32];
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";

        let mut encrypted =
            encrypt_xchacha20_poly1305_blake3_ctx(&key, plaintext_secret_data, authenticated_data)
                .unwrap();
        encrypted.authenticated_data[0] = encrypted.authenticated_data[0].wrapping_add(1);
        let result = decrypt_xchacha20_poly1305_blake3_ctx(&key, &encrypted);
        assert!(result.is_err());
    }
}
