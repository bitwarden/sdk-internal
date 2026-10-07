use bitwarden_auth::{
    AuthClientExt as _,
    send_access::{SendAccessTokenError, SendAccessTokenRequest, SendAccessTokenResponse},
};
use bitwarden_core::{Client, ClientSettings};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    AccessSendError, GetFileDownloadDataError, SendAccessDecryptError, SendAccessKey,
    SendAccessKeyError, SendAccessResponse, SendAccessView, SendFileDownloadData,
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

    /// Requests a send access token from the identity server of the instance this client targets.
    ///
    /// For a password-protected Send, the request's credentials carry the hash returned by
    /// [`Self::hash_send_password`]. Minting the token here, rather than through a signed-in
    /// client, guarantees it (and any password hash) is only ever sent to the server that hosts
    /// the Send.
    pub async fn request_send_access_token(
        &self,
        request: SendAccessTokenRequest,
    ) -> Result<SendAccessTokenResponse, SendAccessTokenError> {
        self.client
            .auth_new()
            .send_access()
            .request_send_access_token(request)
            .await
    }

    /// Hash `password` with the URL-safe-base64 send key into the `password_hash_b64` credential
    /// expected by [`Self::request_send_access_token`].
    pub fn hash_send_password(
        &self,
        key_b64: String,
        password: String,
    ) -> Result<String, SendAccessKeyError> {
        Ok(SendAccessKey::from_url_b64(&key_b64)?.hash_password_b64(&password))
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

    // ===== Network calls go to the configured instance =====

    use bitwarden_auth::send_access::{
        SendAccessCredentials, SendAccessTokenError, SendAccessTokenRequest,
        SendPasswordCredentials,
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, method, path},
    };

    fn client_for(server: &MockServer) -> SendReceiveClient {
        SendReceiveClient::new(Some(ClientSettings {
            api_url: format!("{}/api", server.uri()),
            identity_url: format!("{}/identity", server.uri()),
            ..Default::default()
        }))
    }

    #[tokio::test]
    async fn access_send_calls_the_configured_api_with_the_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/sends/access"))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer the-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "access-id",
                "type": 0,
                "name": "encrypted-name",
                "text": { "text": "encrypted-text", "hidden": false },
            })))
            .expect(1)
            .mount(&server)
            .await;

        let response = client_for(&server)
            .access_send("the-token".to_owned())
            .await
            .expect("access succeeds");

        assert_eq!(response.id.as_deref(), Some("access-id"));
    }

    #[tokio::test]
    async fn get_file_download_data_calls_the_configured_api() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/sends/access/file/file-id"))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer the-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "file-id",
                "url": "https://files.example.invalid/blob",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let data = client_for(&server)
            .get_file_download_data("the-token".to_owned(), "file-id".to_owned())
            .await
            .expect("download data resolves");

        assert_eq!(
            data.url.as_deref(),
            Some("https://files.example.invalid/blob")
        );
    }

    #[tokio::test]
    async fn request_send_access_token_goes_to_the_configured_identity_server() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .and(body_string_contains("send_id=send-id"))
            .and(body_string_contains("password_hash_b64=hash"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-token",
                "token_type": "bearer",
                "expires_in": 3600,
                "scope": "api.send.access",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let token = client_for(&server)
            .request_send_access_token(SendAccessTokenRequest {
                send_id: "send-id".to_owned(),
                send_access_credentials: Some(SendAccessCredentials::Password(
                    SendPasswordCredentials {
                        password_hash_b64: "hash".to_owned(),
                    },
                )),
            })
            .await
            .expect("token is minted");

        assert_eq!(token.token, "minted-token");
    }

    #[tokio::test]
    async fn request_send_access_token_surfaces_server_rejection() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let err = client_for(&server)
            .request_send_access_token(SendAccessTokenRequest {
                send_id: "send-id".to_owned(),
                send_access_credentials: None,
            })
            .await
            .unwrap_err();

        assert!(matches!(err, SendAccessTokenError::Unexpected(_)));
    }

    #[test]
    fn hash_send_password_matches_send_access_key() {
        let expected = SendAccessKey::from_url_b64(URL_KEY)
            .unwrap()
            .hash_password_b64("hunter2");

        let hash = client()
            .hash_send_password(URL_KEY.to_owned(), "hunter2".to_owned())
            .expect("hashes");

        assert_eq!(hash, expected);
    }

    #[test]
    fn hash_send_password_rejects_malformed_key() {
        let err = client()
            .hash_send_password("not valid base64!".to_owned(), "hunter2".to_owned())
            .unwrap_err();

        assert!(matches!(err, SendAccessKeyError::InvalidEncoding));
    }
}
