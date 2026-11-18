use std::path::Path;

use bitwarden_vault::{
    Attachment, AttachmentEncryptResult, AttachmentView, AttachmentViewV2, Cipher,
};

use crate::Result;

#[derive(uniffi::Object)]
pub struct AttachmentsClient(pub(crate) bitwarden_vault::AttachmentsClient);

#[uniffi::export]
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

    /// Encrypt an attachment file in memory, using a fully decrypted attachment view
    pub fn encrypt_buffer_v2(
        &self,
        cipher: Cipher,
        attachment: AttachmentViewV2,
        buffer: Vec<u8>,
    ) -> Result<AttachmentEncryptResult> {
        Ok(self.0.encrypt_buffer_v2(cipher, attachment, &buffer)?)
    }

    /// Encrypt an attachment file located in the file system, using a fully decrypted attachment
    /// view
    pub fn encrypt_file_v2(
        &self,
        cipher: Cipher,
        attachment: AttachmentViewV2,
        decrypted_file_path: String,
        encrypted_file_path: String,
    ) -> Result<Attachment> {
        Ok(self.0.encrypt_file_v2(
            cipher,
            attachment,
            Path::new(&decrypted_file_path),
            Path::new(&encrypted_file_path),
        )?)
    }

    /// Decrypt an attachment file in memory, using a fully decrypted attachment view
    pub fn decrypt_buffer_v2(
        &self,
        cipher: Cipher,
        attachment: AttachmentViewV2,
        buffer: Vec<u8>,
    ) -> Result<Vec<u8>> {
        Ok(self.0.decrypt_buffer_v2(cipher, attachment, &buffer)?)
    }

    /// Decrypt an attachment file located in the file system, using a fully decrypted attachment
    /// view
    pub fn decrypt_file_v2(
        &self,
        cipher: Cipher,
        attachment: AttachmentViewV2,
        encrypted_file_path: String,
        decrypted_file_path: String,
    ) -> Result<()> {
        Ok(self.0.decrypt_file_v2(
            cipher,
            attachment,
            Path::new(&encrypted_file_path),
            Path::new(&decrypted_file_path),
        )?)
    }
}
