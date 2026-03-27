use std::path::{Path, PathBuf};

use bitwarden_send::{Send, SendFileView, SendListView, SendView};

use crate::Result;

/// A single file entry for the file-based send folder builder.
#[derive(uniffi::Record)]
pub struct MakeSendFolderFileUniFFIEntry {
    /// Relative path of the file within the zip archive, using forward slashes.
    pub path: String,
    /// Filesystem path to the source file.
    pub source: String,
}

/// Result of creating a zipped send folder on disk.
#[derive(uniffi::Record)]
pub struct MakeSendFolderFileUniFFIResult {
    /// Metadata for the resulting zip file, suitable for creating a file Send.
    pub file: SendFileView,
}

#[derive(uniffi::Object)]
pub struct SendClient(pub(crate) bitwarden_send::SendClient);

#[uniffi::export]
impl SendClient {
    /// Encrypt send
    pub fn encrypt(&self, send: SendView) -> Result<Send> {
        Ok(self.0.encrypt(send)?)
    }

    /// Encrypt a send file in memory
    pub fn encrypt_buffer(&self, send: Send, buffer: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.0.encrypt_buffer(send, &buffer)?)
    }

    /// Encrypt a send file located in the file system
    pub fn encrypt_file(
        &self,
        send: Send,
        decrypted_file_path: String,
        encrypted_file_path: String,
    ) -> Result<()> {
        Ok(self.0.encrypt_file(
            send,
            Path::new(&decrypted_file_path),
            Path::new(&encrypted_file_path),
        )?)
    }

    /// Decrypt send
    pub fn decrypt(&self, send: Send) -> Result<SendView> {
        Ok(self.0.decrypt(send)?)
    }

    /// Decrypt send list
    pub fn decrypt_list(&self, sends: Vec<Send>) -> Result<Vec<SendListView>> {
        Ok(self.0.decrypt_list(sends)?)
    }

    /// Decrypt a send file in memory
    pub fn decrypt_buffer(&self, send: Send, buffer: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.0.decrypt_buffer(send, &buffer)?)
    }

    /// Zip files from disk into a single archive and write it to the destination path.
    pub fn make_send_folder_file(
        &self,
        folder_name: String,
        files: Vec<MakeSendFolderFileUniFFIEntry>,
        destination: String,
    ) -> Result<MakeSendFolderFileUniFFIResult> {
        let result = self
            .0
            .make_send_folder_file(bitwarden_send::MakeSendFolderFileRequest {
                folder_name,
                files: files
                    .into_iter()
                    .map(|f| bitwarden_send::MakeSendFolderFileEntry {
                        path: f.path,
                        source: PathBuf::from(f.source),
                    })
                    .collect(),
                destination: PathBuf::from(destination),
            })?;
        Ok(MakeSendFolderFileUniFFIResult { file: result.file })
    }

    /// Decrypt a send file located in the file system
    pub fn decrypt_file(
        &self,
        send: Send,
        encrypted_file_path: String,
        decrypted_file_path: String,
    ) -> Result<()> {
        Ok(self.0.decrypt_file(
            send,
            Path::new(&encrypted_file_path),
            Path::new(&decrypted_file_path),
        )?)
    }
}
