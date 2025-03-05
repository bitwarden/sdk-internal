use std::rc::Rc;

use bitwarden_core::Client;
use bitwarden_vault::{Cipher, CipherView, DecryptError, EncryptError, VaultClientExt};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub struct ClientCiphers(Rc<Client>);

impl ClientCiphers {
    pub fn new(client: Rc<Client>) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl ClientCiphers {
    /// Encrypt cipher
    ///
    /// # Arguments
    /// - `cipher_view` - The decrypted cipher to encrypt
    ///
    /// # Returns
    /// - `Ok(Cipher)` containing the encrypted cipher
    /// - `Err(EncryptError)` if encryption fails
    pub fn encrypt(&self, cipher_view: CipherView) -> Result<Cipher, EncryptError> {
        self.0.vault().ciphers().encrypt(cipher_view)
    }

    /// Decrypt cipher
    ///
    /// # Arguments
    /// - `cipher` - The encrypted cipher to decrypt
    ///
    /// # Returns
    /// - `Ok(CipherView)` containing the decrypted cipher
    /// - `Err(DecryptError)` if decryption fails
    pub fn decrypt(&self, cipher: Cipher) -> Result<CipherView, DecryptError> {
        self.0.vault().ciphers().decrypt(cipher)
    }
}
