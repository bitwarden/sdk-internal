#[cfg(feature = "wasm")]
use bitwarden_core::key_management::KeySlotIds;
#[cfg(feature = "wasm")]
use bitwarden_crypto::{CompositeEncryptable, KeyStore, SymmetricCryptoKey};
#[cfg(feature = "wasm")]
use bitwarden_encoding::B64;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
use crate::{
    Send, SendView, send::ItemSendFormat, send_client::SendClient, send_client::SendEncryptError,
};

/// Re-wraps a send's per-item key under `new_key`; the send's content stays under its own
/// unchanged key.
#[cfg(feature = "wasm")]
fn encrypt_send_for_rotation(
    key_store: &KeyStore<KeySlotIds>,
    send_view: SendView,
    new_key: B64,
) -> Result<Send, SendEncryptError> {
    let new_key = SymmetricCryptoKey::try_from(new_key)?;

    let mut ctx = key_store.context();

    // `Local` slot, not the view's natural `User` slot — passed explicitly to `encrypt_composite`.
    let new_key_id = ctx.add_local_symmetric_key(new_key);

    Ok(send_view.encrypt_composite(&mut ctx, new_key_id)?)
}

/// [`encrypt_send_for_rotation`], with Item Send content in the sealed blob format
/// ([`Send::data_v2`]).
#[cfg(feature = "wasm")]
fn encrypt_send_for_rotation_v2(
    key_store: &KeyStore<KeySlotIds>,
    send_view: SendView,
    new_key: B64,
) -> Result<Send, SendEncryptError> {
    let new_key = SymmetricCryptoKey::try_from(new_key)?;

    let mut ctx = key_store.context();

    // `Local` slot, not the view's natural `User` slot, passed explicitly.
    let new_key_id = ctx.add_local_symmetric_key(new_key);

    Ok(send_view.encrypt_with_item_format(&mut ctx, new_key_id, ItemSendFormat::SealedBlob)?)
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl SendClient {
    /// Encrypt a send with the provided key. This should only be used when rotating encryption
    /// keys in the Web client.
    ///
    /// Until Typescript based key-rotation is removed after completing the rollout of sdk-based
    /// key-rotation, this method must be provided the new symmetric key in base64 format. See
    /// PM-23084
    // `async` mirrors `encrypt_cipher_for_rotation`; this rotation does no async work itself.
    #[allow(clippy::unused_async)]
    pub async fn encrypt_send_for_rotation(
        &self,
        send_view: SendView,
        new_key: B64,
    ) -> Result<Send, SendEncryptError> {
        let key_store = self.client.internal.get_key_store();

        encrypt_send_for_rotation(key_store, send_view, new_key)
    }

    /// Encrypt a send with the provided key, with Item Send content in the sealed blob format
    /// ([`Send::data_v2`]). [`SendClient::encrypt_send_for_rotation`] produces the
    /// [`Send::data`] format. This should only be used when rotating encryption keys in the Web
    /// client.
    ///
    /// Item Sends require `CipherView.id`, and partial (restricted) cipher views are refused.
    // `async` mirrors `encrypt_send_for_rotation`; this rotation does no async work itself.
    #[allow(clippy::unused_async)]
    pub async fn encrypt_send_for_rotation_v2(
        &self,
        send_view: SendView,
        new_key: B64,
    ) -> Result<Send, SendEncryptError> {
        let key_store = self.client.internal.get_key_store();

        encrypt_send_for_rotation_v2(key_store, send_view, new_key)
    }
}

#[cfg(test)]
#[cfg(feature = "wasm")]
mod tests {
    use bitwarden_core::key_management::create_test_crypto_with_user_key;
    use bitwarden_crypto::{CryptoError, SymmetricCryptoKey, SymmetricKeyAlgorithm};

    use super::*;
    use crate::{AuthType, SendTextView, SendType, send::tests::item_send_view};

    fn test_send_view() -> SendView {
        SendView {
            id: "3d80dd72-2d14-4f26-812c-b0f0018aa144".parse().ok(),
            access_id: Some("ct2APRQtJk-BLLDwAYqhRA".to_owned()),
            name: "Test".to_string(),
            notes: None,
            key: Some("Pgui0FK85cNhBGWHAlBHBw".to_owned()),
            new_password: None,
            has_password: false,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("This is a test".to_owned()),
                hidden: false,
            }),
            data: None,
            max_access_count: None,
            access_count: 0,
            disabled: false,
            hide_email: false,
            revision_date: "2024-01-07T23:56:48.207363Z".parse().unwrap(),
            deletion_date: "2024-01-14T23:56:48Z".parse().unwrap(),
            expiration_date: None,
            emails: Vec::new(),
            auth_type: AuthType::None,
        }
    }

    #[test]
    fn test_encrypt_send_for_rotation() {
        let user_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let store = create_test_crypto_with_user_key(user_key);

        let new_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let new_key_b64 = new_key.to_base64();

        let send_view = test_send_view();

        let rotated = encrypt_send_for_rotation(&store, send_view.clone(), new_key_b64).unwrap();

        // Round-trips under the new key.
        let new_store = create_test_crypto_with_user_key(new_key);
        let decrypted: SendView = new_store.decrypt(&rotated).unwrap();
        assert_eq!(decrypted.name, send_view.name);
        assert_eq!(decrypted.text, send_view.text);

        // Fails under the old key, since the send key was re-wrapped.
        assert!(matches!(
            store.decrypt::<_, Send, SendView>(&rotated).err(),
            Some(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn test_encrypt_send_for_rotation_v2_round_trip() {
        let user_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let store = create_test_crypto_with_user_key(user_key);

        let new_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let new_key_b64 = new_key.to_base64();

        let send_view = item_send_view();

        let rotated = encrypt_send_for_rotation_v2(&store, send_view.clone(), new_key_b64).unwrap();

        assert!(rotated.data.is_none());
        assert!(rotated.data_v2.is_some());

        // Round-trips under the new key, item id restored from the metadata.
        let new_store = create_test_crypto_with_user_key(new_key);
        let decrypted: SendView = new_store.decrypt(&rotated).unwrap();
        assert_eq!(decrypted, send_view);

        // Fails under the old key, since the send key was re-wrapped.
        assert!(matches!(
            store.decrypt::<_, Send, SendView>(&rotated).err(),
            Some(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn test_encrypt_send_for_rotation_produces_serialized_cipher() {
        let user_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let store = create_test_crypto_with_user_key(user_key);

        let new_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);

        let rotated =
            encrypt_send_for_rotation(&store, item_send_view(), new_key.to_base64()).unwrap();

        assert!(rotated.data.is_some());
        assert!(rotated.data_v2.is_none());
    }
}
