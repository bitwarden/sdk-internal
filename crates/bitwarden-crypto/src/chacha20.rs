use crate::CryptoError;
use aes_gcm_siv::Aes256GcmSiv;
use chacha20poly1305::consts::U32;
use chacha20poly1305::AeadCore;
use chacha20poly1305::AeadInPlace;
use chacha20poly1305::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use generic_array::GenericArray;
use rand::rngs::OsRng;

pub fn encrypt_xchacha20_poly1305(
    secret_data: &[u8],
    authenticated_data: &[u8],
    key: &[u8; 32],
) -> Result<([u8; 24], Vec<u8>), CryptoError> {
    let key_generic_array = GenericArray::from_slice(key);

    let cipher = XChaCha20Poly1305::new(&key_generic_array);
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    // to dyn buf
    let mut buffer = secret_data.to_vec();
    let ciphertext = cipher.encrypt_in_place(&nonce, &[], &mut buffer);
    match ciphertext {
        Ok(_) => Ok((nonce.into(), buffer)),
        Err(_) => Err(CryptoError::InvalidKey),
    }
}

pub fn decrypt_xchacha20_poly1305(
    nonce: &[u8; 24],
    authenticated_data: &[u8],
    key: &GenericArray<u8, U32>,
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(&key);
    let nonce = GenericArray::from_slice(nonce);
    let mut buffer = data.to_vec();
    let plaintext = cipher.decrypt_in_place(&nonce, &[], &mut buffer);
    match plaintext {
        Ok(_) => Ok(buffer),
        Err(_) => Err(CryptoError::InvalidKey),
    }
}

pub fn encrypt_aes_256_gcm_siv(
    secret_data: &[u8],
    authenticated_data: &[u8],
    key: &[u8; 32],
) -> Result<([u8; 12], Vec<u8>), CryptoError> {
    let key_generic_array = GenericArray::from_slice(key);

    let cipher = Aes256GcmSiv::new(&key_generic_array);
    let nonce = Aes256GcmSiv::generate_nonce(&mut OsRng);
    // to dyn buf
    let mut buffer = secret_data.to_vec();
    let ciphertext = cipher.encrypt_in_place(&nonce, &[], &mut buffer);
    match ciphertext {
        Ok(_) => Ok((nonce.into(), buffer)),
        Err(_) => Err(CryptoError::InvalidKey),
    }
}

pub fn decrypt_aes_256_gcm_siv(
    nonce: &[u8; 12],
    authenticated_data: &[u8],
    key: &GenericArray<u8, U32>,
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256GcmSiv::new(&key);
    let nonce = GenericArray::from_slice(nonce);
    let mut buffer = data.to_vec();
    let plaintext = cipher.decrypt_in_place(&nonce, &[], &mut buffer);
    match plaintext {
        Ok(_) => Ok(buffer),
        Err(_) => Err(CryptoError::InvalidKey),
    }
}
