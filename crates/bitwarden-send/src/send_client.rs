use std::{path::Path, sync::Arc};

use bitwarden_core::Client;
use bitwarden_crypto::{
    Decryptable, EncString, IdentifyKey, OctetStreamBytes, PrimitiveEncryptable,
};
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    MakeSendMultiFileError, MakeSendMultiFilePathRequest, MakeSendMultiFilePathResult,
    MakeSendMultiFileRequest, MakeSendMultiFileResult, Send, SendListView, SendView,
};

/// Generic error type for send encryption errors.
#[allow(missing_docs)]
#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum SendEncryptError {
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

/// Generic error type for send decryption errors
#[allow(missing_docs)]
#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum SendDecryptError {
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

/// Generic error type for send encryption errors.
#[allow(missing_docs)]
#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum SendEncryptFileError {
    #[error(transparent)]
    Encrypt(#[from] SendEncryptError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Generic error type for send decryption errors
#[allow(missing_docs)]
#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum SendDecryptFileError {
    #[error(transparent)]
    Decrypt(#[from] SendDecryptError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct SendClient {
    pub(crate) client: Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl SendClient {
    /// Zip the provided files into a single archive and return the zip bytes along with
    /// [`SendFileView`](crate::SendFileView) metadata suitable for creating a file Send.
    pub fn make_send_multi_file(
        &self,
        request: MakeSendMultiFileRequest,
    ) -> Result<MakeSendMultiFileResult, MakeSendMultiFileError> {
        crate::multi_file::make_send_multi_file(request)
    }
}

impl SendClient {
    fn new(client: Client) -> Self {
        Self { client }
    }

    #[allow(missing_docs)]
    pub fn decrypt(&self, send: Send) -> Result<SendView, SendDecryptError> {
        let key_store = self.client.internal.get_key_store();
        let send_view = key_store.decrypt(&send)?;
        Ok(send_view)
    }

    #[allow(missing_docs)]
    pub fn decrypt_list(&self, sends: Vec<Send>) -> Result<Vec<SendListView>, SendDecryptError> {
        let key_store = self.client.internal.get_key_store();
        let send_views = key_store.decrypt_list(&sends)?;
        Ok(send_views)
    }

    #[allow(missing_docs)]
    pub fn decrypt_file(
        &self,
        send: Send,
        encrypted_file_path: &Path,
        decrypted_file_path: &Path,
    ) -> Result<(), SendDecryptFileError> {
        let data = std::fs::read(encrypted_file_path)?;
        let decrypted = self.decrypt_buffer(send, &data)?;
        std::fs::write(decrypted_file_path, decrypted)?;
        Ok(())
    }

    #[allow(missing_docs)]
    pub fn decrypt_buffer(
        &self,
        send: Send,
        encrypted_buffer: &[u8],
    ) -> Result<Vec<u8>, SendDecryptError> {
        let key_store = self.client.internal.get_key_store();
        let mut ctx = key_store.context();

        let key = Send::get_key(&mut ctx, &send.key, send.key_identifier())?;

        let buf = EncString::from_buffer(encrypted_buffer)?;
        Ok(buf.decrypt(&mut ctx, key)?)
    }

    #[allow(missing_docs)]
    pub fn encrypt(&self, send_view: SendView) -> Result<Send, SendEncryptError> {
        let key_store = self.client.internal.get_key_store();

        let send = key_store.encrypt(send_view)?;

        Ok(send)
    }

    #[allow(missing_docs)]
    pub fn encrypt_file(
        &self,
        send: Send,
        decrypted_file_path: &Path,
        encrypted_file_path: &Path,
    ) -> Result<(), SendEncryptFileError> {
        let data = std::fs::read(decrypted_file_path)?;
        let encrypted = self.encrypt_buffer(send, &data)?;
        std::fs::write(encrypted_file_path, encrypted)?;
        Ok(())
    }

    #[allow(missing_docs)]
    pub fn encrypt_buffer(&self, send: Send, buffer: &[u8]) -> Result<Vec<u8>, SendEncryptError> {
        let key_store = self.client.internal.get_key_store();
        let mut ctx = key_store.context();

        let key = Send::get_key(&mut ctx, &send.key, send.key_identifier())?;

        let encrypted = OctetStreamBytes::from(buffer).encrypt(&mut ctx, key)?;
        Ok(encrypted.to_buffer()?)
    }

    /// Zip files from disk into a single archive and write it to the destination path.
    pub fn make_send_multi_file_path(
        &self,
        request: MakeSendMultiFilePathRequest,
    ) -> Result<MakeSendMultiFilePathResult, MakeSendMultiFileError> {
        crate::multi_file::make_send_multi_file_path(request)
    }
}

impl SendClient {
    pub(crate) fn get_repository(&self) -> Result<Arc<dyn Repository<Send>>, RepositoryError> {
        Ok(self.client.platform().state().get::<Send>()?)
    }
}

#[allow(missing_docs)]
pub trait SendClientExt {
    fn sends(&self) -> SendClient;
}

impl SendClientExt for Client {
    fn sends(&self) -> SendClient {
        SendClient::new(self.clone())
    }
}
