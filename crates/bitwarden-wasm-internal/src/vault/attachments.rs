use bitwarden_vault::{Attachment, Cipher, DecryptError};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub struct ClientAttachments(bitwarden_vault::ClientAttachments);

impl ClientAttachments {
    pub fn new(client: bitwarden_vault::ClientAttachments) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl ClientAttachments {
    /// Decrypts an attachment's encrypted content
    pub fn decrypt_buffer(
        &self,
        cipher: Cipher,
        attachment: Attachment,
        encrypted_buffer: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        self.0.decrypt_buffer(cipher, attachment, encrypted_buffer)
    }
}
