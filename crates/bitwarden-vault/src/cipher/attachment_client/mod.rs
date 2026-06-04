use std::{path::Path, sync::Arc};

use bitwarden_core::{FromClient, client::ApiConfigurations, key_management::KeySlotIds};
use bitwarden_crypto::{EncString, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::Repository;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Attachment, AttachmentEncryptResult, AttachmentFile, AttachmentFileView, AttachmentView,
    Cipher, DecryptError, EncryptError,
};

mod admin;
mod create;
mod delete;
mod download_url;
mod renew;
mod upgrade;

pub use admin::{
    AttachmentAdminClient, CipherAdminGetAttachmentDownloadUrlError, DeleteAttachmentAdminError,
};
pub use create::{
    AttachmentFileUploadType, CipherCreateAttachmentError, CreateAttachmentRequest,
    CreatedAttachment,
};
pub use delete::CipherDeleteAttachmentError;
pub use download_url::CipherGetAttachmentDownloadUrlError;
pub use renew::CipherRenewFileUploadUrlError;
pub use upgrade::CipherUpgradeAttachmentError;

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

/// Wrapper for attachment-specific cipher operations.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct AttachmentsClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
    pub(crate) repository: Option<Arc<dyn Repository<Cipher>>>,
    pub(crate) http_client: reqwest::Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl AttachmentsClient {
    /// Returns a new client for performing attachment admin operations.
    /// Uses the admin server API endpoints and does not modify local state.
    pub fn admin(&self) -> AttachmentAdminClient {
        AttachmentAdminClient {
            api_configurations: self.api_configurations.clone(),
        }
    }

    #[allow(missing_docs)]
    pub fn decrypt_buffer(
        &self,
        cipher: Cipher,
        attachment: AttachmentView,
        encrypted_buffer: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        Ok(self.key_store.decrypt(&AttachmentFile {
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
        Ok(self.key_store.encrypt(AttachmentFileView {
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
