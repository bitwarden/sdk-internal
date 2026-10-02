use std::path::Path;

use bitwarden_crypto::EncString;
use bitwarden_vault::{
    Attachment, AttachmentEncryptResult, AttachmentView, Cipher, CipherId, CipherView,
    CreatedAttachment,
};
use chrono::{DateTime, Utc};

use crate::Result;

/// Request to create an attachment slot on a cipher.
///
/// Mirrors [`bitwarden_vault::CreateAttachmentRequest`] without its admin flag, since mobile never
/// uses the admin endpoints.
#[derive(uniffi::Record)]
pub struct CreateAttachmentRequest {
    /// Encrypted attachment key.
    pub key: EncString,
    /// Encrypted file name.
    pub file_name: EncString,
    /// Encrypted file size in bytes.
    pub file_size: u64,
    /// Cipher revision date
    pub last_known_revision_date: DateTime<Utc>,
}

impl From<CreateAttachmentRequest> for bitwarden_vault::CreateAttachmentRequest {
    fn from(request: CreateAttachmentRequest) -> Self {
        Self {
            key: request.key,
            file_name: request.file_name,
            file_size: request.file_size,
            last_known_revision_date: request.last_known_revision_date,
            as_admin: false,
        }
    }
}

#[derive(uniffi::Object)]
pub struct AttachmentsClient(pub(crate) bitwarden_vault::AttachmentsClient);

#[uniffi::export(async_runtime = "tokio")]
impl AttachmentsClient {
    /// Encrypt an attachment file in memory
    pub fn encrypt_buffer(
        &self,
        cipher: Cipher,
        attachment: AttachmentView,
        buffer: Vec<u8>,
    ) -> Result<AttachmentEncryptResult> {
        Ok(self.0.encrypt_buffer(cipher, attachment, &buffer)?)
    }

    /// Encrypt an attachment file located in the file system
    pub fn encrypt_file(
        &self,
        cipher: Cipher,
        attachment: AttachmentView,
        decrypted_file_path: String,
        encrypted_file_path: String,
    ) -> Result<Attachment> {
        Ok(self.0.encrypt_file(
            cipher,
            attachment,
            Path::new(&decrypted_file_path),
            Path::new(&encrypted_file_path),
        )?)
    }
    /// Decrypt an attachment file in memory
    pub fn decrypt_buffer(
        &self,
        cipher: Cipher,
        attachment: AttachmentView,
        buffer: Vec<u8>,
    ) -> Result<Vec<u8>> {
        Ok(self.0.decrypt_buffer(cipher, attachment, &buffer)?)
    }

    /// Decrypt an attachment file located in the file system
    pub fn decrypt_file(
        &self,
        cipher: Cipher,
        attachment: AttachmentView,
        encrypted_file_path: String,
        decrypted_file_path: String,
    ) -> Result<()> {
        Ok(self.0.decrypt_file(
            cipher,
            attachment,
            Path::new(&encrypted_file_path),
            Path::new(&decrypted_file_path),
        )?)
    }

    /// Create an attachment on a cipher, returning the URL the encrypted file should be uploaded
    /// to and the updated cipher
    pub async fn create_attachment(
        &self,
        cipher_id: CipherId,
        request: CreateAttachmentRequest,
    ) -> Result<CreatedAttachment> {
        Ok(self.0.create_attachment(cipher_id, request.into()).await?)
    }

    /// Delete an attachment from a cipher, returning the updated cipher
    pub async fn delete_attachment(
        &self,
        cipher_id: CipherId,
        attachment_id: String,
    ) -> Result<Cipher> {
        Ok(self.0.delete_attachment(cipher_id, attachment_id).await?)
    }

    /// Get a renewed upload URL for an attachment. Does not modify the attachment slot.
    pub async fn renew_file_upload_url(
        &self,
        cipher_id: CipherId,
        attachment_id: String,
    ) -> Result<String> {
        Ok(self
            .0
            .renew_file_upload_url(cipher_id, attachment_id)
            .await?)
    }

    /// Re-encrypt a legacy attachment that has no attachment key, returning the updated cipher
    pub async fn upgrade_attachment(
        &self,
        cipher_id: CipherId,
        attachment_id: String,
    ) -> Result<CipherView> {
        Ok(self.0.upgrade_attachment(cipher_id, attachment_id).await?)
    }

    /// Get the download URL for an attachment. Pass `emergency_access_id` when downloading
    /// through emergency access.
    pub async fn get_attachment_download_url(
        &self,
        cipher_id: CipherId,
        attachment_id: String,
        emergency_access_id: Option<String>,
    ) -> Result<String> {
        Ok(self
            .0
            .get_attachment_download_url(cipher_id, attachment_id, emergency_access_id)
            .await?)
    }
}
