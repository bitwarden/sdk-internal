use std::{path::Path, sync::Arc};

use bitwarden_core::Client;
use bitwarden_crypto::{
    Decryptable, EncString, IdentifyKey, OctetStreamBytes, PrimitiveEncryptable,
};
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    Send, SendListView, SendView,
    create::{CreateSendError, SendAddEditRequest, create_send},
    edit::{EditSendError, edit_send},
    get_list::{GetSendError, get_send, list_sends},
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
    client: Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
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

    /// Create a new [Send] and save it to the server.
    pub async fn create(&self, request: SendAddEditRequest) -> Result<SendView, CreateSendError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations().await;
        let repository = self.get_repository()?;

        create_send(key_store, &config.api_client, repository.as_ref(), request).await
    }

    /// Edit the [Folder] and save it to the server.
    pub async fn edit(
        &self,
        send_id: Uuid,
        request: SendAddEditRequest,
    ) -> Result<SendView, EditSendError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations().await;
        let repository = self.get_repository()?;

        edit_send(
            key_store,
            &config.api_client,
            repository.as_ref(),
            send_id,
            request,
        )
        .await
    }

    /// Get all sends from state and decrypt them to a list of [SendView].
    pub async fn list(&self) -> Result<Vec<SendView>, GetSendError> {
        let key_store = self.client.internal.get_key_store();
        let repository = self.get_repository()?;

        list_sends(key_store, repository.as_ref()).await
    }

    /// Get a specific [Send] by its ID from state and decrypt it to a [SendView].
    pub async fn get(&self, send_id: Uuid) -> Result<SendView, GetSendError> {
        let key_store = self.client.internal.get_key_store();
        let repository = self.get_repository()?;

        get_send(key_store, repository.as_ref(), send_id).await
    }
}

impl SendClient {
    /// Helper for getting the repository for sends.
    fn get_repository(&self) -> Result<Arc<dyn Repository<Send>>, RepositoryError> {
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
