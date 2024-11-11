use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use rand::rngs::OsRng;

use crate::CryptoError;

fn generate_x25519_keypair()  -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let secret = StaticSecret::new(OsRng);
    let public = PublicKey::from(&secret);
    let secret_bytes: Vec<u8> = secret.to_bytes().to_vec();
    let public_bytes = public.as_bytes().to_vec();
    Ok((secret_bytes.to_vec(), public_bytes))
}

fn derive_shared(pubkey: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let pubkey_fixed: [u8; 32] = pubkey.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let public = PublicKey::from(pubkey_fixed);
    let secret = EphemeralSecret::new(OsRng);
    let shared_secret = secret.diffie_hellman(&public);
    Ok(shared_secret.as_bytes().to_vec())
}