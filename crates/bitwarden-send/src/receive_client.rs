use bitwarden_core::{Client, ClientSettings};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    AccessSendError, GetFileDownloadDataError, SendAccessDecryptError, SendAccessKey,
    SendAccessResponse, SendAccessView, SendFileDownloadData,
    access::{access_send, get_file_download_data},
};

/// Client dedicated to receiving (anonymously accessing) a Send.
///
/// Receiving is the only Send operation that may target a different Bitwarden instance than the
/// one the user is signed into: the target server is dictated by the Send link itself (e.g. a
/// self-hosted or other-region server). This client is therefore built from its own
/// [`ClientSettings`] and carries no user identity, tokens, or key store. Creating and editing
/// Sends never needs this, and should go through the regular
/// [`SendClient`](crate::SendClient).
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct SendReceiveClient {
    client: Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl SendReceiveClient {
    /// Create a receive client targeting the instance described by `settings`.
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    pub fn new(settings: Option<ClientSettings>) -> Self {
        Self {
            client: Client::new(settings),
        }
    }

    /// Accesses a send, authenticated with a send access token.
    /// The returned [SendAccessResponse] contains encrypted fields that must be decrypted
    /// with [`Self::decrypt_send_access`] using the key from the URL fragment.
    pub async fn access_send(
        &self,
        access_token: String,
    ) -> Result<SendAccessResponse, AccessSendError> {
        let config = self.client.internal.get_api_configurations();
        access_send(&config.api_client, &access_token).await
    }

    /// Gets file download data for a file send, authenticated with a send access token.
    pub async fn get_file_download_data(
        &self,
        access_token: String,
        file_id: String,
    ) -> Result<SendFileDownloadData, GetFileDownloadDataError> {
        let config = self.client.internal.get_api_configurations();
        get_file_download_data(&config.api_client, &file_id, &access_token).await
    }

    /// Decrypt a [`SendAccessResponse`] into a [`SendAccessView`] using the URL-safe-base64 send
    /// key from the trailing segment of the send URL fragment.
    pub fn decrypt_send_access(
        &self,
        key_b64: String,
        response: SendAccessResponse,
    ) -> Result<SendAccessView, SendAccessDecryptError> {
        SendAccessKey::from_url_b64(&key_b64)?.decrypt_response(response)
    }

    /// Decrypt a downloaded file-send blob using the URL-safe-base64 send key.
    pub fn decrypt_send_access_file(
        &self,
        key_b64: String,
        buffer: &[u8],
    ) -> Result<Vec<u8>, SendAccessDecryptError> {
        SendAccessKey::from_url_b64(&key_b64)?.decrypt_file_buffer(buffer)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::{ClientSettings, key_management::create_test_crypto_with_user_key};
    use bitwarden_crypto::{OctetStreamBytes, PrimitiveEncryptable as _, SymmetricCryptoKey};
    use bitwarden_encoding::B64Url;

    use super::*;
    use crate::{Send, SendAccessKeyError, SendAccessTextResponse, SendType};

    /// The url-safe-base64 form of a 16-byte send key, as it appears in a send URL fragment.
    const URL_KEY: &str = "Pgui0FK85cNhBGWHAlBHBw";
    const USER_KEY: &str =
        "bYCsk857hl8QJJtxyRK65tjUrbxKC4aDifJpsml+NIv4W9cVgFvi3qVD+yJTUU2T4UwNKWYtt9pqWf7Q+2WCCg==";

    fn client() -> SendReceiveClient {
        SendReceiveClient::new(Some(ClientSettings {
            api_url: "https://api.example.invalid".to_owned(),
            identity_url: "https://identity.example.invalid".to_owned(),
            ..Default::default()
        }))
    }

    /// Encrypt `plaintext` with the key an anonymous receiver derives from [`URL_KEY`],
    /// using the same derivation the authenticated send-creation path uses.
    fn encrypt_with_url_key(plaintext: &str) -> String {
        let user_key: SymmetricCryptoKey = USER_KEY.to_string().try_into().unwrap();
        let store = create_test_crypto_with_user_key(user_key);
        let mut ctx = store.context();
        let raw = B64Url::try_from(URL_KEY).unwrap().into_bytes();
        let key = Send::derive_shareable_key(&mut ctx, &raw).unwrap();
        plaintext.encrypt(&mut ctx, key).unwrap().to_string()
    }

    fn response(name: &str, text: &str) -> SendAccessResponse {
        SendAccessResponse {
            id: Some("access-id".to_owned()),
            type_: Some(SendType::Text),
            name: Some(encrypt_with_url_key(name)),
            text: Some(SendAccessTextResponse {
                text: Some(encrypt_with_url_key(text)),
                hidden: false,
            }),
            file: None,
            data: None,
            expiration_date: None,
            creator_identifier: None,
        }
    }

    #[test]
    fn new_accepts_default_and_custom_settings() {
        let _ = SendReceiveClient::new(None);
        let _ = client();
    }

    #[test]
    fn new_targets_the_configured_instance() {
        let client = client();
        let config = client.client.internal.get_api_configurations();
        assert_eq!(config.api_config.base_path, "https://api.example.invalid");
    }

    #[test]
    fn decrypt_send_access_round_trips() {
        let view = client()
            .decrypt_send_access(URL_KEY.to_owned(), response("Test", "This is a test"))
            .expect("decrypts");

        assert_eq!(view.name.as_deref(), Some("Test"));
        assert_eq!(
            view.text.expect("text present").text.as_deref(),
            Some("This is a test")
        );
    }

    #[test]
    fn decrypt_send_access_rejects_malformed_key() {
        let err = client()
            .decrypt_send_access("not valid base64!".to_owned(), response("Test", "x"))
            .unwrap_err();

        assert!(matches!(
            err,
            SendAccessDecryptError::Key(SendAccessKeyError::InvalidEncoding)
        ));
    }

    #[test]
    fn decrypt_send_access_rejects_wrong_length_key() {
        let err = client()
            .decrypt_send_access("AAAA".to_owned(), response("Test", "x"))
            .unwrap_err();

        assert!(matches!(
            err,
            SendAccessDecryptError::Key(SendAccessKeyError::InvalidLength)
        ));
    }

    #[test]
    fn decrypt_send_access_errors_on_wrong_key() {
        // A valid 16-byte key that differs from the one the response was encrypted with.
        let other_key = "AAAAAAAAAAAAAAAAAAAAAA";
        let err = client()
            .decrypt_send_access(other_key.to_owned(), response("Test", "x"))
            .unwrap_err();

        assert!(matches!(err, SendAccessDecryptError::Crypto(_)));
    }

    #[test]
    fn decrypt_send_access_file_round_trips() {
        let plaintext = b"file send contents".to_vec();
        let user_key: SymmetricCryptoKey = USER_KEY.to_string().try_into().unwrap();
        let store = create_test_crypto_with_user_key(user_key);
        let mut ctx = store.context();
        let raw = B64Url::try_from(URL_KEY).unwrap().into_bytes();
        let key = Send::derive_shareable_key(&mut ctx, &raw).unwrap();
        let encrypted = OctetStreamBytes::from(plaintext.clone())
            .encrypt(&mut ctx, key)
            .unwrap()
            .to_buffer()
            .unwrap();

        let decrypted = client()
            .decrypt_send_access_file(URL_KEY.to_owned(), &encrypted)
            .expect("decrypts");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_send_access_file_rejects_malformed_key() {
        let err = client()
            .decrypt_send_access_file("not valid base64!".to_owned(), b"irrelevant")
            .unwrap_err();

        assert!(matches!(
            err,
            SendAccessDecryptError::Key(SendAccessKeyError::InvalidEncoding)
        ));
    }

    #[test]
    fn decrypt_send_access_file_errors_on_garbage_blob() {
        let err = client()
            .decrypt_send_access_file(URL_KEY.to_owned(), b"not an encstring")
            .unwrap_err();

        assert!(matches!(err, SendAccessDecryptError::Crypto(_)));
    }
}
