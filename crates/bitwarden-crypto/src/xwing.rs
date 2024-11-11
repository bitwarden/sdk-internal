use std::io::Read;

use ml_kem::kem::Encapsulate;
use ml_kem::kem::Decapsulate;
use crate::{CryptoError};

pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let mut rng = rand::thread_rng();
    let (sk, pk) = x_wing::generate_key_pair(&mut rng);
    let sk_bytes = sk.as_bytes();
    let pk_bytes = pk.as_bytes();
    Ok((sk_bytes.to_vec(), pk_bytes.to_vec()))
}

pub fn encapsulate(pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let pk_fixed_slize: &[u8; 1216] = pk.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let mut rng = rand::thread_rng();
    let pk = x_wing::EncapsulationKey::from(pk_fixed_slize);
    let (ct, ss_sender) = pk.encapsulate(&mut rng).unwrap();
    Ok((ct.as_bytes().to_vec(), ss_sender.to_vec()))
}

pub fn decapsulate(sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sk_fixed_slize: [u8; 32] = sk.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let ct_fixed_slize: &[u8; 1120] = ct.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let sk = x_wing::DecapsulationKey::from(sk_fixed_slize);
    let ct = x_wing::Ciphertext::from(ct_fixed_slize);
    let ss_receiver = sk.decapsulate(&ct).unwrap();
    Ok(ss_receiver.to_vec())
}