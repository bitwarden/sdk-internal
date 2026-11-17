use std::{path::Path, sync::Arc};

use bitwarden_core::Client;
use bitwarden_crypto::{
    Decryptable, EncString, IdentifyKey, OctetStreamBytes, PrimitiveEncryptable,
};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{Send, SendListView, SendView, send::ItemSendFormat};

/// Generic error type for send encryption errors.
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum SendEncryptError {
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

/// Generic error type for send decryption errors
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
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

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl SendClient {
    /// Decrypt a [`Send`] into a [`SendView`].
    /// This is a temporary function to support the transition to fully using the SDK for Send logic
    pub fn decrypt_send(&self, send: Send) -> Result<SendView, SendDecryptError> {
        self.decrypt(send)
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

    /// Encrypt a [`SendView`] into a [`Send`] whose item content is in the sealed blob format
    /// ([`Send::data_v2`]). [`SendClient::encrypt`] produces the [`Send::data`] format.
    ///
    /// Item Sends require `CipherView.id`, and partial (restricted) cipher views are refused.
    /// Text and File Sends encrypt the same as with [`SendClient::encrypt`].
    pub fn encrypt_v2(&self, send_view: SendView) -> Result<Send, SendEncryptError> {
        let key_store = self.client.internal.get_key_store();
        let mut ctx = key_store.context();

        let send = send_view.encrypt_with_item_format(
            &mut ctx,
            send_view.key_identifier(),
            ItemSendFormat::SealedBlob,
        )?;

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

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey};

    use super::*;
    use crate::send::tests::{TEST_USER_KEY, item_send_view};

    fn test_client() -> Client {
        let client = Client::new(None);
        let user_key: SymmetricCryptoKey = TEST_USER_KEY.to_string().try_into().unwrap();
        let key_store: &KeyStore<KeySlotIds> = client.internal.get_key_store();
        let mut ctx = key_store.context_mut();
        let local_key_id = ctx.add_local_symmetric_key(user_key);
        ctx.persist_symmetric_key(local_key_id, SymmetricKeySlotId::User)
            .unwrap();
        drop(ctx);
        client
    }

    #[test]
    fn test_encrypt_v2_produces_sealed_blob_and_decrypts() {
        let client = test_client();
        let sends = client.sends();

        let send = sends.encrypt_v2(item_send_view()).unwrap();

        assert!(send.data.is_none());
        let item = send.data_v2.as_ref().unwrap();
        assert_eq!(
            item.metadata.item_id,
            item_send_view().data.unwrap().data.id.unwrap()
        );

        assert_eq!(sends.decrypt(send).unwrap(), item_send_view());
    }

    #[test]
    fn test_encrypt_produces_serialized_cipher() {
        let client = test_client();

        let send = client.sends().encrypt(item_send_view()).unwrap();

        assert!(send.data.is_some());
        assert!(send.data_v2.is_none());
    }

    #[test]
    fn test_encrypt_v2_requires_item_id() {
        let client = test_client();
        let mut view = item_send_view();
        view.data.as_mut().unwrap().data.id = None;

        let result = client.sends().encrypt_v2(view);

        assert!(matches!(
            result,
            Err(SendEncryptError::Crypto(
                bitwarden_crypto::CryptoError::MissingField("id")
            ))
        ));
    }
}
