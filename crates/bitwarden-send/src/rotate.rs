#[cfg(feature = "wasm")]
use bitwarden_core::key_management::KeySlotIds;
#[cfg(feature = "wasm")]
use bitwarden_crypto::{CompositeEncryptable, KeyStore, SymmetricCryptoKey};
#[cfg(feature = "wasm")]
use bitwarden_encoding::B64;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
use crate::{Send, SendView, send_client::SendClient, send_client::SendEncryptError};

/// Re-encrypt a send using the provided key. Only the per-send key is re-wrapped under `new_key`;
/// the send's content stays encrypted under the send's own (unchanged) derived key.
#[cfg(feature = "wasm")]
fn encrypt_send_for_rotation(
    key_store: &KeyStore<KeySlotIds>,
    send_view: SendView,
    new_key: B64,
) -> Result<Send, SendEncryptError> {
    let new_key = SymmetricCryptoKey::try_from(new_key)?;

    let mut ctx = key_store.context();

    // Install the new key under a `Local` slot id rather than the view's natural `User` slot, then
    // pass it explicitly to `encrypt_composite`. Unlike ciphers, a send always carries its own
    // per-item key (`Send::key`), so rotation simply re-wraps that key under `new_key` — there is
    // no "generate a new item key" branch to handle.
    let new_key_id = ctx.add_local_symmetric_key(new_key);

    Ok(send_view.encrypt_composite(&mut ctx, new_key_id)?)
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl SendClient {
    /// Encrypt a send with the provided key. This should only be used when rotating encryption
    /// keys in the Web client.
    ///
    /// Until key rotation is fully implemented in the SDK, this method must be provided the new
    /// symmetric key in base64 format. See PM-23084
    ///
    /// The send's per-item key is re-encrypted with the new key. The send's content is not
    /// re-encrypted, as it is encrypted under the send's own key which does not change during
    /// rotation.
    // `async` mirrors `encrypt_cipher_for_rotation` and lets callers await rotation methods
    // uniformly; the underlying send rotation performs no async work.
    #[allow(clippy::unused_async)]
    pub async fn encrypt_send_for_rotation(
        &self,
        send_view: SendView,
        new_key: B64,
    ) -> Result<Send, SendEncryptError> {
        let key_store = self.client.internal.get_key_store();

        encrypt_send_for_rotation(key_store, send_view, new_key)
    }
}

#[cfg(test)]
#[cfg(feature = "wasm")]
mod tests {
    use bitwarden_core::key_management::create_test_crypto_with_user_key;
    use bitwarden_crypto::{CryptoError, SymmetricCryptoKey, SymmetricKeyAlgorithm};

    use super::*;
    use crate::{AuthType, SendTextView, SendType};

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

        // Decrypting with a key store holding the new key succeeds and round-trips the view.
        let new_store = create_test_crypto_with_user_key(new_key);
        let decrypted: SendView = new_store.decrypt(&rotated).unwrap();
        assert_eq!(decrypted.name, send_view.name);
        assert_eq!(decrypted.text, send_view.text);

        // Decrypting with the original key store fails because the send key was re-wrapped under
        // the new key.
        assert!(matches!(
            store.decrypt::<_, Send, SendView>(&rotated).err(),
            Some(CryptoError::Decrypt)
        ));
    }
}
