/**
* Note:
* XChaCha20Poly1305-CTX encrypts data, and authenticates associated data using XChaCha20Poly1305
* Specifically, this uses the CTX construction, proposed here: https://par.nsf.gov/servlets/purl/10391723
* using blake3 as the cryptographic hash function. This provides not only key-commitment, but full-commitment.
* In total, this scheme prevents attacks such as invisible salamanders.
*/

use crate::CryptoError;
use chacha20poly1305::AeadCore;
use chacha20poly1305::AeadInPlace;
use chacha20poly1305::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20::XChaCha20;
use generic_array::GenericArray;
use poly1305::Poly1305;
use subtle::ConstantTimeEq;
use chacha20::cipher::{KeyIvInit, StreamCipher};

use poly1305::universal_hash::UniversalHash;

pub struct XChaCha20Poly1305CTXCiphetext {
    nonce: [u8; 24],
    tag: [u8; 32],
    ciphertext: Vec<u8>,
    authenticated_data: Vec<u8>,
}

#[allow(dead_code)]
pub fn encrypt_xchacha20_poly1305_blake3_ctx(
    key: &[u8; 32],
    plaintext_secret_data: &[u8],
    authenticated_data: &[u8],
) -> Result<XChaCha20Poly1305CTXCiphetext, CryptoError> {
    encrypt_xchacha20_poly1305_blake3_ctx_internal(rand::thread_rng(), key, plaintext_secret_data, authenticated_data)
}

#[allow(dead_code)]
fn encrypt_xchacha20_poly1305_blake3_ctx_internal(
    rng: impl rand::CryptoRng + rand::RngCore,
    key: &[u8; 32],
    plaintext_secret_data: &[u8],
    associated_data: &[u8],
) -> Result<XChaCha20Poly1305CTXCiphetext, CryptoError> {
    let mut buffer = Vec::from(plaintext_secret_data);
    let cipher = XChaCha20Poly1305::new(&GenericArray::from_slice(key));
    let nonce = XChaCha20Poly1305::generate_nonce(rng);
    
    let poly1305_tag = cipher.encrypt_in_place_detached(&nonce, associated_data, &mut buffer).map_err(|_| CryptoError::InvalidKey)?;
    
    // T* = H(K, N, A, T )
    let ctx_tag = blake3::hash(&[key, nonce.as_slice(), associated_data, poly1305_tag.as_slice()].concat());
    let ctx_tag = ctx_tag.as_bytes();

    Ok(XChaCha20Poly1305CTXCiphetext {
        nonce: nonce.as_slice().try_into().unwrap(),
        ciphertext: buffer,
        authenticated_data: associated_data.to_vec(),
        tag: *ctx_tag,
    })
}

#[allow(dead_code)]
pub fn decrypt_xchacha20_poly1305_blake3_ctx(
    key: &[u8; 32],
    ctx: &XChaCha20Poly1305CTXCiphetext,
) -> Result<Vec<u8>, CryptoError> {
    let buffer = ctx.ciphertext.clone();
    let associated_data = ctx.authenticated_data.as_slice();

    // First, get the original polynomial tag, since this is required to calculate the ctx_tag
    let poly1305_tag = get_tag_expected_for_xchacha20_poly1305_ctx(key, &ctx.nonce, associated_data, &buffer); 
   
    let ctx_tag = blake3::hash(&[key, ctx.nonce.as_slice(), associated_data, poly1305_tag.as_slice()].concat());
    let ctx_tag = ctx_tag.as_bytes();

    if ctx_tag.ct_eq(&ctx.tag).into() {
        // At this point the commitment is verified, so we can decrypt the data using regular XChaCha20Poly1305
        let cipher = XChaCha20Poly1305::new(&GenericArray::from_slice(key));
        let mut buffer = ctx.ciphertext.clone();
        let nonce_array = GenericArray::from_slice(&ctx.nonce);
        cipher.decrypt_in_place_detached(nonce_array, associated_data, &mut buffer, &poly1305_tag)
            .map_err(|_| CryptoError::InvalidKey)?;
        return Ok(buffer);
    }

    Err(CryptoError::InvalidKey)
}

fn get_tag_expected_for_xchacha20_poly1305_ctx(key: &[u8; 32], nonce: &[u8; 24], associated_data: &[u8], buffer: &[u8]) -> chacha20poly1305::Tag {
    let mut chacha20 = XChaCha20::new(GenericArray::from_slice(key), GenericArray::from_slice(nonce));
    let mut mac_key = poly1305::Key::default();
    chacha20.apply_keystream(&mut *mac_key);
    let mut mac = Poly1305::new(GenericArray::from_slice(&*mac_key));
    mac.update_padded(&associated_data);
    mac.update_padded(&buffer);
    authenticate_lengths(&associated_data, &buffer, &mut mac);
    mac.finalize()
}

fn authenticate_lengths(associated_data: &[u8], buffer: &[u8], mac: &mut Poly1305) -> () {
    let associated_data_len: u64 = associated_data.len() as u64;
    let buffer_len: u64 = buffer.len() as u64;

    let mut block = GenericArray::default();
    block[..8].copy_from_slice(&associated_data_len.to_le_bytes());
    block[8..].copy_from_slice(&buffer_len.to_le_bytes());
    mac.update(&[block]);
}

mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_xchacha20_poly1305_ctx() {
        let key = [0u8; 32];
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";

        let encrypted = encrypt_xchacha20_poly1305_blake3_ctx(&key, plaintext_secret_data, authenticated_data).unwrap();
        let decrypted = decrypt_xchacha20_poly1305_blake3_ctx(&key, &encrypted).unwrap();
        assert_eq!(plaintext_secret_data, decrypted.as_slice());
    }
}