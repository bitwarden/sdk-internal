use std::{num::NonZero, rc::Rc};

use bitwarden_core::{
    mobile::crypto::{InitOrgCryptoRequest, InitUserCryptoRequest},
    Client,
};
use bitwarden_crypto::{chacha20, xwing};
use wasm_bindgen::prelude::*;

use crate::error::Result;

#[wasm_bindgen]
pub struct ClientCrypto(Rc<Client>);

impl ClientCrypto {
    pub fn new(client: Rc<Client>) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl ClientCrypto {
    /// Initialization method for the user crypto. Needs to be called before any other crypto
    /// operations.
    pub async fn initialize_user_crypto(&self, req: InitUserCryptoRequest) -> Result<()> {
        Ok(self.0.crypto().initialize_user_crypto(req).await?)
    }

    /// Initialization method for the organization crypto. Needs to be called after
    /// `initialize_user_crypto` but before any other crypto operations.
    pub async fn initialize_org_crypto(&self, req: InitOrgCryptoRequest) -> Result<()> {
        Ok(self.0.crypto().initialize_org_crypto(req).await?)
    }

    pub fn decrypt_loop_xchacha(data: &[u8], key: &[u8], iterations: u32) -> Result<Vec<u8>> {
        let mut data = data.to_vec();
        for n in 0..iterations {
            let iter_data = Self::decrypt_xchacha20_poly1305(&data, key)?;
            data = iter_data;
        }
        Ok(data)
    }

    pub fn decrypt_loop_aes(data: &[u8], key: &[u8], iterations: u32) -> Result<Vec<u8>> {
        let mut data = data.to_vec();
        let mut counter: u32 = 0;
        for n in 0..iterations {
            let iter_data = Self::decrypt_aes_256_gcm_siv(&data, key)?;
            // get nth value
            let n = iter_data[(n % iter_data.len() as u32) as usize];
            data = iter_data;
            counter += 1;
        }

        data.append(&mut counter.to_be_bytes().to_vec());
        Ok(data)
    }

    pub fn decrypt_xchacha20_poly1305(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        let nonce = data[..24].try_into().unwrap();
        let ciphertext = &data[24..];
        let key_len32 = key[..32].try_into().unwrap();
        let plaintext = chacha20::decrypt_xchacha20_poly1305(&nonce, &[], key_len32, ciphertext)?;
        Ok(plaintext)
    }

    pub fn encrypt_xchacha20_poly1305(
        secret_data: &[u8],
        authenticated_data: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>> {
        let key_len32 = key[..32].try_into().unwrap();
        let (nonce, ciphertext) =
            chacha20::encrypt_xchacha20_poly1305(secret_data, authenticated_data, key_len32)?;
        let result: Vec<u8> = nonce.into_iter().chain(ciphertext.into_iter()).collect();
        Ok(result)
    }

    pub fn decrypt_aes_256_gcm_siv(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        let nonce = data[..12].try_into().unwrap();
        let ciphertext = &data[12..];
        let key_len32 = key[..32].try_into().unwrap();
        let plaintext = chacha20::decrypt_aes_256_gcm_siv(&nonce, &[], key_len32, ciphertext)?;
        Ok(plaintext)
    }

    pub fn encrypt_aes_256_gcm_siv(
        secret_data: &[u8],
        authenticated_data: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>> {
        let key_len32 = key[..32].try_into().unwrap();
        let (nonce, ciphertext) =
            chacha20::encrypt_aes_256_gcm_siv(secret_data, authenticated_data, key_len32)?;
        let result: Vec<u8> = nonce.into_iter().chain(ciphertext.into_iter()).collect();
        Ok(result)
    }

    pub fn generate_xwing_keypair() -> Result<Vec<u8>> {
        let (sk, pk) = xwing::generate_keypair()?;
        // concat
        let concat = sk.to_vec().into_iter().chain(pk.to_vec().into_iter()).collect();
        Ok(concat)
    }

    pub fn encapsulate_xwing(vec: Vec<u8>) -> Result<Vec<u8>> {
        let (ct, ss_sender) = xwing::encapsulate(&vec)?;
        let concat = ct.to_vec().into_iter().chain(ss_sender.to_vec().into_iter()).collect();
        Ok(concat)
    }

    pub fn decapsulate_xwing(sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        let ss_receiver = xwing::decapsulate(sk, ct)?;
        Ok(ss_receiver.to_vec())
    }

    pub fn generate_ed25519_keypair() -> Result<Vec<u8>> {
        let (sk, pk) = bitwarden_crypto::ed25519::generate_ed25519_keypair()?;
        // concat
        let concat = sk.to_vec().into_iter().chain(pk.to_vec().into_iter()).collect();
        Ok(concat)
    }

    pub fn sign_ed25519(data: Vec<u8>, secret: Vec<u8>) -> Result<Vec<u8>> {
        let signature = bitwarden_crypto::ed25519::sign(data, secret)?;
        Ok(signature)
    }

    pub fn verify_ed25519(data: Vec<u8>, signature: Vec<u8>, public: Vec<u8>) -> Result<bool> {
        let res = bitwarden_crypto::ed25519::verify(data, signature, public)?;
        Ok(res)
    }

}