use std::{num::NonZero, rc::Rc};

use bitwarden_core::{
    mobile::crypto::{InitOrgCryptoRequest, InitUserCryptoRequest},
    Client,
};
use bitwarden_crypto::chacha20;
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

    pub fn encrypt_xchacha20_poly1305(
        secret_data: &[u8],
        authenticated_data: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>> {
        println!("encrypt_xchacha20_poly1305");
        println!("secret_data {:?}", secret_data);
        println!("authenticated_data {:?}", authenticated_data);
        println!("key {:?}", key);
        let key_len32 = key[..32].try_into().unwrap();
        let (nonce, ciphertext) =
            chacha20::encrypt_xchacha20_poly1305(secret_data, authenticated_data, key_len32)?;
        println!("encrytped");
        let result: Vec<u8> = nonce.into_iter().chain(ciphertext.into_iter()).collect();
        println!("result {:?}", result);
        Ok(result)
    }
}
