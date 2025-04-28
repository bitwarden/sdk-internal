use bitwarden_vault::{
    Cipher, CipherError, CipherListView, CipherView, DecryptError, EncryptError,
    Fido2CredentialView,
};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub struct CiphersClient(bitwarden_vault::CiphersClient);

impl CiphersClient {
    pub fn new(client: bitwarden_vault::CiphersClient) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl CiphersClient {
    /// Encrypt cipher
    ///
    /// # Arguments
    /// - `cipher_view` - The decrypted cipher to encrypt
    ///
    /// # Returns
    /// - `Ok(Cipher)` containing the encrypted cipher
    /// - `Err(EncryptError)` if encryption fails
    pub fn encrypt(&self, cipher_view: CipherView) -> Result<Cipher, EncryptError> {
        self.0.encrypt(cipher_view)
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
        self.0.decrypt(cipher)
    }

    /// Decrypt list of ciphers
    ///
    /// # Arguments
    /// - `ciphers` - The list of encrypted ciphers to decrypt
    ///
    /// # Returns
    /// - `Ok(Vec<CipherListView>)` containing the decrypted ciphers
    /// - `Err(DecryptError)` if decryption fails
    pub fn decrypt_list(&self, ciphers: Vec<Cipher>) -> Result<Vec<CipherListView>, DecryptError> {
        self.0.decrypt_list(ciphers)
    }

    /// Decrypt FIDO2 credentials
    ///
    /// # Arguments
    /// - `cipher_view` - Cipher to encrypt containing the FIDO2 credential
    ///
    /// # Returns
    /// - `Ok(Vec<Fido2CredentialView>)` containing the decrypted FIDO2 credentials
    /// - `Err(DecryptError)` if decryption fails
    pub fn decrypt_fido2_credentials(
        &self,
        cipher_view: CipherView,
    ) -> Result<Vec<Fido2CredentialView>, DecryptError> {
        self.0.decrypt_fido2_credentials(cipher_view)
    }

    /// Decrypt key
    ///
    /// This method is a temporary solution to allow typescript client access to decrypted key
    /// values, particularly for FIDO2 credentials.
    ///
    /// # Arguments
    /// - `cipher_view` - Decrypted cipher containing the key
    ///
    /// # Returns
    /// - `Ok(String)` containing the decrypted key
    /// - `Err(CipherError)`
    pub fn decrypt_fido2_private_key(
        &self,
        cipher_view: CipherView,
    ) -> Result<String, CipherError> {
        self.0.decrypt_fido2_private_key(cipher_view)
    }
}
