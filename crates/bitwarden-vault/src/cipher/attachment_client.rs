use std::path::Path;

use bitwarden_core::Client;
use bitwarden_crypto::EncString;
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Attachment, AttachmentEncryptResult, AttachmentFile, AttachmentFileView, AttachmentView,
    Cipher, DecryptError, EncryptError,
};

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct AttachmentsClient {
    pub(crate) client: Client,
}

/// Generic error type for vault encryption errors.
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EncryptFileError {
    #[error(transparent)]
    Encrypt(#[from] EncryptError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Generic error type for decryption errors
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum DecryptFileError {
    #[error(transparent)]
    Decrypt(#[from] DecryptError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl AttachmentsClient {
    #[allow(missing_docs)]
    pub fn decrypt_buffer(
        &self,
        cipher: Cipher,
        attachment: AttachmentView,
        encrypted_buffer: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let key_store = self.client.internal.get_key_store();

        Ok(key_store.decrypt(&AttachmentFile {
            cipher,
            attachment,
            contents: EncString::from_buffer(encrypted_buffer)?,
        })?)
    }
}

impl AttachmentsClient {
    #[allow(missing_docs)]
    pub fn encrypt_buffer(
        &self,
        cipher: Cipher,
        attachment: AttachmentView,
        buffer: &[u8],
    ) -> Result<AttachmentEncryptResult, EncryptError> {
        let key_store = self.client.internal.get_key_store();

        Ok(key_store.encrypt(AttachmentFileView {
            cipher,
            attachment,
            contents: buffer,
        })?)
    }

    #[allow(missing_docs)]
    pub fn encrypt_file(
        &self,
        cipher: Cipher,
        attachment: AttachmentView,
        decrypted_file_path: &Path,
        encrypted_file_path: &Path,
    ) -> Result<Attachment, EncryptFileError> {
        let data = std::fs::read(decrypted_file_path)?;
        let AttachmentEncryptResult {
            attachment,
            contents,
        } = self.encrypt_buffer(cipher, attachment, &data)?;
        std::fs::write(encrypted_file_path, contents)?;
        Ok(attachment)
    }

    #[allow(missing_docs)]
    pub fn decrypt_file(
        &self,
        cipher: Cipher,
        attachment: AttachmentView,
        encrypted_file_path: &Path,
        decrypted_file_path: &Path,
    ) -> Result<(), DecryptFileError> {
        let data = std::fs::read(encrypted_file_path)?;
        let decrypted = self.decrypt_buffer(cipher, attachment, &data)?;
        std::fs::write(decrypted_file_path, decrypted)?;
        Ok(())
    }
}
