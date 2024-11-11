use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rsa::signature::SignerMut;

use crate::CryptoError;

pub fn generate_ed25519_keypair()  -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let secret = SigningKey::generate(&mut OsRng);
    let public = VerifyingKey::from(&secret);
    let secret_bytes: Vec<u8> = secret.to_bytes().to_vec();
    let public_bytes = public.as_bytes().to_vec();
    Ok((secret_bytes.to_vec(), public_bytes))
}

pub fn sign(data: Vec<u8>, secret: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let secret_fixed: [u8; 32] = secret.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let mut secret = SigningKey::from_bytes(&secret_fixed);
    let data_fixed: &[u8] = data.as_slice();
    let signature = secret.sign(data_fixed);
    Ok(signature.to_bytes().to_vec())
}

pub fn verify(data: Vec<u8>, signature: Vec<u8>, public: Vec<u8>) -> Result<bool, CryptoError> {
    let public_fixed: [u8; 32] = public.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let public = VerifyingKey::from_bytes(&public_fixed).map_err(|_| CryptoError::InvalidKey)?;
    let data_fixed: &[u8] = data.as_slice();
    let signature_fixed: [u8; 64] = signature.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_fixed);
    let res = public.verify_strict(data_fixed, &signature).map_err(|_| CryptoError::InvalidKey);
    Ok(res.is_ok())
}