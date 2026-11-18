//! [`AttachmentsClient`] operations that take and return the fully decrypted
//! [`AttachmentViewV2`] and [`CipherViewV2`] models.
//!
//! Each `_v2` method converts its input to the [`AttachmentView`] model, runs the operation of the
//! same name without the suffix, and converts the result back.

use std::path::Path;

use bitwarden_crypto::{CryptoError, IdentifyKey};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::{
    AttachmentsClient, DecryptFileError, EncryptFileError, upgrade::CipherUpgradeAttachmentError,
};
use crate::{
    Attachment, AttachmentEncryptResult, AttachmentView, AttachmentViewV2, Cipher, CipherId,
    CipherViewV2, DecryptError, EncryptError, cipher::cipher_view_v2::view_to_v2,
};

impl AttachmentsClient {
    /// Wraps the attachment key under the key of `cipher`.
    fn attachment_to_v1(
        &self,
        cipher: &Cipher,
        attachment: &AttachmentViewV2,
    ) -> Result<AttachmentView, CryptoError> {
        let mut ctx = self.key_store.context();
        let cipher_key =
            Cipher::decrypt_cipher_key(&mut ctx, cipher.key_identifier(), &cipher.key)?;
        attachment.to_v1(&mut ctx, cipher_key)
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl AttachmentsClient {
    /// [`AttachmentsClient::decrypt_buffer`] for the [`AttachmentViewV2`] model.
    pub fn decrypt_buffer_v2(
        &self,
        cipher: Cipher,
        attachment: AttachmentViewV2,
        encrypted_buffer: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let attachment = self.attachment_to_v1(&cipher, &attachment)?;
        self.decrypt_buffer(cipher, attachment, encrypted_buffer)
    }

    /// [`AttachmentsClient::upgrade_attachment`] for the [`CipherViewV2`] model.
    pub async fn upgrade_attachment_v2(
        &self,
        cipher_id: CipherId,
        attachment_id: String,
    ) -> Result<CipherViewV2, CipherUpgradeAttachmentError> {
        let view = self.upgrade_attachment(cipher_id, attachment_id).await?;
        Ok(view_to_v2(&self.key_store, &view)?)
    }
}

impl AttachmentsClient {
    /// [`AttachmentsClient::encrypt_buffer`] for the [`AttachmentViewV2`] model.
    pub fn encrypt_buffer_v2(
        &self,
        cipher: Cipher,
        attachment: AttachmentViewV2,
        buffer: &[u8],
    ) -> Result<AttachmentEncryptResult, EncryptError> {
        let attachment = self.attachment_to_v1(&cipher, &attachment)?;
        self.encrypt_buffer(cipher, attachment, buffer)
    }

    /// [`AttachmentsClient::encrypt_file`] for the [`AttachmentViewV2`] model.
    pub fn encrypt_file_v2(
        &self,
        cipher: Cipher,
        attachment: AttachmentViewV2,
        decrypted_file_path: &Path,
        encrypted_file_path: &Path,
    ) -> Result<Attachment, EncryptFileError> {
        let attachment = self
            .attachment_to_v1(&cipher, &attachment)
            .map_err(EncryptError::from)?;
        self.encrypt_file(cipher, attachment, decrypted_file_path, encrypted_file_path)
    }

    /// [`AttachmentsClient::decrypt_file`] for the [`AttachmentViewV2`] model.
    pub fn decrypt_file_v2(
        &self,
        cipher: Cipher,
        attachment: AttachmentViewV2,
        encrypted_file_path: &Path,
        decrypted_file_path: &Path,
    ) -> Result<(), DecryptFileError> {
        let attachment = self
            .attachment_to_v1(&cipher, &attachment)
            .map_err(DecryptError::from)?;
        self.decrypt_file(cipher, attachment, encrypted_file_path, decrypted_file_path)
    }
}
