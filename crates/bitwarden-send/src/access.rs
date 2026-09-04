use bitwarden_api_api::{
    apis::ApiClient,
    models::{self, SendEncryptionType},
};
use bitwarden_core::{ApiError, key_management::KeySlotIds};
use bitwarden_crypto::{
    CryptoError, Decryptable, EncString, KeyDecryptable as _, KeyStore, SymmetricCryptoKey,
    derive_shareable_key,
};
use bitwarden_encoding::{B64, B64Url};
use bitwarden_error::bitwarden_error;
use bitwarden_vault::{Cipher, CipherView};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{SendParseError, SendType, send::SEND_ITERATIONS, send_client::SendClient};

/// Length in bytes of the raw Send key carried in a Send URL fragment. `pub(crate)` so
/// `SendView::encrypt_composite` (`send.rs`) can generate keys of exactly this length,
/// enforcing the relationship at compile time instead of relying on a test to catch drift.
pub(crate) const SEND_KEY_LEN: usize = 16;

// ===== Public output types (returned to callers) =====

/// View of a send's accessible content, returned after a successful send access call.
/// Name, text, file, and item fields are encrypted and must be decrypted client-side
/// using the key derived from the URL fragment.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[bitwarden_ffi::wasm_record]
pub struct SendAccessResponse {
    /// The send access ID
    pub id: Option<String>,
    /// The send type.
    #[serde(rename = "type")]
    pub type_: Option<SendType>,
    /// Encrypted send name
    pub name: Option<String>,
    /// Text content (if type is Text)
    pub text: Option<SendAccessTextResponse>,
    /// File metadata (if type is File)
    pub file: Option<SendAccessFileResponse>,
    /// Item metadata (if type is Item)
    pub data: Option<SendAccessItemResponse>,
    /// When the send expires.
    pub expiration_date: Option<DateTime<Utc>>,
    /// The creator's identifier (email), if not hidden
    pub creator_identifier: Option<String>,
}

/// Encrypted text content of a text send.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[bitwarden_ffi::wasm_record]
pub struct SendAccessTextResponse {
    /// Encrypted text content
    pub text: Option<String>,
    /// Whether to hide the text by default
    pub hidden: bool,
}

/// Encrypted file metadata of a file send.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[bitwarden_ffi::wasm_record]
pub struct SendAccessFileResponse {
    /// The file ID
    pub id: Option<String>,
    /// Encrypted file name
    pub file_name: Option<String>,
    /// File size in bytes as a string
    pub size: Option<String>,
    /// Human-readable size (e.g. "4.2 KB")
    pub size_name: Option<String>,
}

/// Encrypted item metadata of an item send.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[bitwarden_ffi::wasm_record]
pub struct SendAccessItemResponse {
    /// The version of encryption used to encrypt the item data
    pub encryption_version: Option<SendEncryptionType>,
    /// The encrypted item data
    pub data: Option<String>,
}

/// File download URL data returned from a send file access call.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[bitwarden_ffi::wasm_record]
pub struct SendFileDownloadData {
    /// The file ID
    pub id: Option<String>,
    /// The pre-signed download URL
    pub url: Option<String>,
}

// ===== Decrypted views of an anonymous send access =====

/// Plaintext view of a [`SendAccessResponse`], produced by
/// [`SendAccessKey::decrypt_response`].
///
/// Mirrors the legacy CLI's `SendAccessResponse` output shape (`apps/cli`) so that a
/// JSON dump of a received send stays recognizable to existing scripts, with two additions:
/// `expirationDate` and `creatorIdentifier` are already present on the raw
/// `SendAccessResponse` the server returns, but the legacy CLI's output shape drops them.
///
/// `text`/`file` are kept as independent `Option`s rather than collapsed into an enum with
/// associated data: `type_` is `Option<SendType>` on the wire and an unrecognized or absent
/// discriminant must still round-trip (both the legacy CLI and `bw receive` fall back to
/// dumping whatever the server returned), which a total enum could not represent.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[bitwarden_ffi::wasm_record]
pub struct SendAccessView {
    /// The send access ID
    pub id: Option<String>,
    /// The send type.
    #[serde(rename = "type")]
    pub type_: Option<SendType>,
    /// The decrypted send name. `None` when the send has no name, which is not an error —
    /// a nameless text send still has printable content.
    pub name: Option<String>,
    /// Decrypted text content (if type is Text)
    pub text: Option<SendAccessTextView>,
    /// Decrypted file metadata (if type is File)
    pub file: Option<SendAccessFileView>,
    /// Decrypted item content (if type is Item)
    pub data: Option<SendAccessItemView>,
    /// When the send expires.
    pub expiration_date: Option<DateTime<Utc>>,
    /// The creator's identifier (email), if not hidden
    pub creator_identifier: Option<String>,
}

/// Decrypted text content of a text send.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[bitwarden_ffi::wasm_record]
pub struct SendAccessTextView {
    /// The decrypted text content
    pub text: Option<String>,
    /// Whether to hide the text by default
    pub hidden: bool,
}

/// Decrypted file metadata of a file send.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[bitwarden_ffi::wasm_record]
pub struct SendAccessFileView {
    /// The file ID
    pub id: Option<String>,
    /// The decrypted file name
    pub file_name: Option<String>,
    /// File size in bytes as a string
    pub size: Option<String>,
    /// Human-readable size (e.g. "4.2 KB")
    pub size_name: Option<String>,
}

/// Decrypted item metadata of an item send.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[bitwarden_ffi::wasm_record]
pub struct SendAccessItemView {
    /// The decrypted Cipher data
    pub data: Option<CipherView>,
}

// ===== Error types =====

/// Error returned when the key from a send URL fragment cannot be turned into a
/// [`SendAccessKey`]. Deliberately carries no key material.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum SendAccessKeyError {
    /// The fragment key was not valid URL-safe base64.
    #[error("The send key is not valid url-safe base64")]
    InvalidEncoding,
    /// The decoded key was not `SEND_KEY_LEN` (16) bytes long.
    #[error("The send key must be {SEND_KEY_LEN} bytes")]
    InvalidLength,
}

/// Error returned when decrypting an anonymous send access response or file blob fails.
/// Wraps [`CryptoError`], which never embeds plaintext or key material in its messages.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum SendAccessDecryptError {
    /// The ciphertext was malformed, or the key derived from the URL fragment does not
    /// decrypt it (wrong key, or a tampered response).
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The key could not be derived from the URL fragment
    #[error(transparent)]
    Key(#[from] SendAccessKeyError),
}

// ===== Anonymous access key =====

/// Symmetric key material for an anonymous Send access, derived entirely from the URL
/// fragment — no account key store or logged-in user involved. This is the only Send flow
/// whose key doesn't come from the user's key store, hence a standalone type rather than a
/// [`bitwarden_crypto::KeyStoreContext`] slot.
///
/// The key is opaque by design: callers need to *use* it three ways (hash a password,
/// decrypt a response, decrypt a downloaded blob) but never need to *see* it.
pub struct SendAccessKey {
    /// The raw fragment key, exactly as decoded from the URL — not run through the KDF that
    /// derives [`Self::key`] below. Retained because the send password hash is salted with
    /// these raw bytes, not with the derived key.
    secret: Zeroizing<[u8; SEND_KEY_LEN]>,
    /// The send's actual symmetric key, derived from `secret` via `derive_shareable_key`.
    /// This is what encrypts the send's fields and file blob.
    key: SymmetricCryptoKey,
}

impl SendAccessKey {
    /// Parse the URL-safe-base64 key from a Send URL fragment and stretch it into the
    /// send's symmetric key. Equivalent to the legacy clients' `Utils.fromUrlB64ToArray`
    /// followed by `KeyService.makeSendKey`.
    ///
    /// The `"send"`/`Some("send")` name/info pair must stay in lockstep with
    /// `Send::derive_shareable_key` — that is what `bw send create` used to encrypt the send,
    /// so any divergence makes every send undecryptable through this path. The round-trip
    /// test below pins the two together.
    pub fn from_url_b64(key_b64: &str) -> Result<Self, SendAccessKeyError> {
        // Wrap the decoded bytes in `Zeroizing` before any length check so a wrong-length
        // key is still scrubbed rather than left in freed memory.
        let decoded = Zeroizing::new(
            B64Url::try_from(key_b64)
                .map_err(|_| SendAccessKeyError::InvalidEncoding)?
                .into_bytes(),
        );
        if decoded.len() != SEND_KEY_LEN {
            return Err(SendAccessKeyError::InvalidLength);
        }
        let mut secret = Zeroizing::new([0u8; SEND_KEY_LEN]);
        secret.copy_from_slice(&decoded);

        let key = SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
            secret.clone(),
            "send",
            Some("send"),
        ));

        Ok(Self { secret, key })
    }

    /// PBKDF2-HMAC-SHA256 over `password`, `SEND_ITERATIONS` (100,000) rounds, salted with the
    /// raw URL key — the `password_hash_b64` credential the send-access token grant expects.
    ///
    /// Identical recipe to `SendAuthType::auth_data`, which is what `bw send create --password`
    /// stored on the server. A pinning test asserts the two agree; if they ever diverge, every
    /// password-protected receive fails with an opaque server-side rejection.
    pub fn hash_password_b64(&self, password: &str) -> String {
        let hashed =
            bitwarden_crypto::pbkdf2(password.as_bytes(), self.secret.as_slice(), SEND_ITERATIONS);
        B64::from(hashed.as_slice()).to_string()
    }

    /// Decrypt a [`SendAccessResponse`]'s encrypted fields into a plaintext
    /// [`SendAccessView`].
    pub fn decrypt_response(
        &self,
        response: SendAccessResponse,
    ) -> Result<SendAccessView, SendAccessDecryptError> {
        let text = match response.text {
            Some(t) => Some(SendAccessTextView {
                text: self.decrypt_optional(t.text)?,
                hidden: t.hidden,
            }),
            None => None,
        };
        let file = match response.file {
            Some(f) => Some(SendAccessFileView {
                id: f.id,
                file_name: self.decrypt_optional(f.file_name)?,
                size: f.size,
                size_name: f.size_name,
            }),
            None => None,
        };
        let data = match response.data {
            Some(d) => {
                let key_store: KeyStore<KeySlotIds> = KeyStore::default();
                let mut ctx = key_store.context_mut();
                let key = ctx.add_local_symmetric_key(self.key.clone());
                let Some(data) = d.data else {
                    return Err(SendAccessDecryptError::Crypto(CryptoError::MissingField(
                        "data",
                    )));
                };
                let cipher = serde_json::from_str::<Cipher>(data.as_str());
                match cipher {
                    Ok(c) => {
                        let cipher_view: CipherView = c.decrypt(&mut ctx, key)?;
                        Some(SendAccessItemView {
                            data: Some(cipher_view),
                        })
                    }
                    Err(_) => None,
                }
            }
            None => None,
        };

        Ok(SendAccessView {
            id: response.id,
            type_: response.type_,
            name: self.decrypt_optional(response.name)?,
            text,
            file,
            data,
            expiration_date: response.expiration_date,
            creator_identifier: response.creator_identifier,
        })
    }

    /// Decrypt a downloaded file-send blob. The blob is a single whole-buffer [`EncString`]
    /// (not the chunked attachment format), matching the legacy clients'
    /// `EncArrayBuffer.fromResponse` + `EncryptService.decryptFileData`.
    pub fn decrypt_file_buffer(&self, buffer: &[u8]) -> Result<Vec<u8>, SendAccessDecryptError> {
        Ok(EncString::from_buffer(buffer)?.decrypt_with_key(&self.key)?)
    }

    /// Parse and decrypt an optional wire-format [`EncString`] field. Absent fields stay
    /// absent — the caller decides whether a missing field is fatal.
    fn decrypt_optional(
        &self,
        value: Option<String>,
    ) -> Result<Option<String>, SendAccessDecryptError> {
        match value {
            Some(s) => Ok(Some(s.parse::<EncString>()?.decrypt_with_key(&self.key)?)),
            None => Ok(None),
        }
    }
}

/// Error returned when accessing a send fails.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessSendError {
    /// An API or network error occurred.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// The response body could not be parsed into a [`SendAccessResponse`] — either a
    /// required field was missing, the send type was an unrecognized value, or a date
    /// field was malformed.
    #[error(transparent)]
    Parse(#[from] SendParseError),
}

/// Error returned when getting send file download data fails.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum GetFileDownloadDataError {
    /// An API or network error occurred.
    #[error(transparent)]
    Api(#[from] ApiError),
}

// ===== HTTP request functions =====

async fn access_send(
    api_client: &ApiClient,
    access_token: &str,
) -> Result<SendAccessResponse, AccessSendError> {
    let resp = api_client
        .sends_api()
        .access_using_auth(access_token)
        .await?;
    Ok(resp.try_into()?)
}

async fn get_file_download_data(
    api_client: &ApiClient,
    file_id: &str,
    access_token: &str,
) -> Result<SendFileDownloadData, GetFileDownloadDataError> {
    let resp = api_client
        .sends_api()
        .get_send_file_download_data_using_auth(file_id, access_token)
        .await?;
    Ok(resp.into())
}

// ===== Conversions from API response models =====

impl TryFrom<models::SendAccessResponseModel> for SendAccessResponse {
    type Error = SendParseError;

    fn try_from(r: models::SendAccessResponseModel) -> Result<Self, Self::Error> {
        Ok(SendAccessResponse {
            id: r.id,
            type_: r.r#type.map(SendType::try_from).transpose()?,
            name: r.name,
            text: r.text.map(|t| SendAccessTextResponse {
                text: t.text,
                hidden: t.hidden.unwrap_or(false),
            }),
            file: r.file.map(|f| SendAccessFileResponse {
                id: f.id,
                file_name: f.file_name,
                size: f.size,
                size_name: f.size_name,
            }),
            data: r.data.map(|dat| SendAccessItemResponse {
                encryption_version: dat.encryption_version,
                data: dat.data,
            }),
            expiration_date: r.expiration_date.map(|s| s.parse()).transpose()?,
            creator_identifier: r.creator_identifier,
        })
    }
}

impl From<models::SendFileDownloadDataResponseModel> for SendFileDownloadData {
    fn from(r: models::SendFileDownloadDataResponseModel) -> Self {
        SendFileDownloadData {
            id: r.id,
            url: r.url,
        }
    }
}

// ===== SendClient methods =====

#[bitwarden_ffi::wasm_export]
impl SendClient {
    /// Accesses a send, authenticated with a send access token.
    /// The returned [SendAccessResponse] contains encrypted fields that must be decrypted
    /// client-side using the key derived from the URL fragment.
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

    /// Decrypt a [`SendAccessResponse`] into a [`SendAccessView`].
    ///
    /// `key_b64` is the URL-safe-base64 send key from the trailing segment of the send URL
    /// fragment (16 bytes when decoded) — the same form [`SendAccessKey::from_url_b64`] accepts
    ///
    /// This is a temporary function to support the transition to fully using the SDK for Send logic
    pub fn decrypt_send_access(
        key_b64: String,
        response: SendAccessResponse,
    ) -> Result<SendAccessView, SendAccessDecryptError> {
        let access_key = SendAccessKey::from_url_b64(key_b64.as_str())?;
        access_key.decrypt_response(response)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            SendAccessResponseModel, SendFileDownloadDataResponseModel, SendFileModel,
            SendTextModel, SendType,
        },
    };

    use super::*;

    const SEND_ID: &str = "25afb11c-9c95-4db5-8bac-c21cb204a3f1";
    const FILE_ID: &str = "file-id-abc";
    const ACCESS_TOKEN: &str = "send-access-token";

    // ===== access_send =====

    #[tokio::test]
    async fn test_access_send_text() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sends_api
                .expect_access_using_auth()
                .returning(|token| {
                    assert_eq!(token, ACCESS_TOKEN);
                    Ok(SendAccessResponseModel {
                        object: Some("send-access".to_string()),
                        id: Some(SEND_ID.to_string()),
                        r#type: Some(SendType::Text),
                        auth_type: None,
                        name: Some("encrypted-name".to_string()),
                        file: None,
                        text: Some(Box::new(SendTextModel {
                            text: Some("encrypted_send_text".to_string()),
                            hidden: Some(true),
                        })),
                        data: None,
                        expiration_date: Some("2025-01-10T00:00:00Z".to_string()),
                        creator_identifier: Some("user@example.com".to_string()),
                    })
                })
                .once();
        });

        let result = access_send(&api_client, ACCESS_TOKEN).await.unwrap();

        assert_eq!(result.id, Some(SEND_ID.to_string()));
        assert_eq!(result.type_, Some(crate::SendType::Text));
        assert_eq!(result.name, Some("encrypted-name".to_string()));
        assert!(result.file.is_none());
        let text = result.text.expect("text variant should be populated");
        assert_eq!(text.text, Some("encrypted_send_text".to_string()));
        assert!(text.hidden);
        assert_eq!(
            result.expiration_date,
            Some("2025-01-10T00:00:00Z".parse::<DateTime<Utc>>().unwrap())
        );
        assert_eq!(
            result.creator_identifier,
            Some("user@example.com".to_string())
        );
    }

    #[tokio::test]
    async fn test_access_send_file() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sends_api
                .expect_access_using_auth()
                .returning(|token| {
                    assert_eq!(token, ACCESS_TOKEN);
                    Ok(SendAccessResponseModel {
                        object: Some("send-access".to_string()),
                        id: Some(SEND_ID.to_string()),
                        r#type: Some(SendType::File),
                        auth_type: None,
                        name: Some("encrypted-name".to_string()),
                        file: Some(Box::new(SendFileModel {
                            id: Some(FILE_ID.to_string()),
                            file_name: Some("encrypted-file-name".to_string()),
                            size: Some("4200".to_string()),
                            size_name: Some("4.2 KB".to_string()),
                        })),
                        text: None,
                        data: None,
                        expiration_date: None,
                        creator_identifier: None,
                    })
                })
                .once();
        });

        let result = access_send(&api_client, ACCESS_TOKEN).await.unwrap();

        assert_eq!(result.id, Some(SEND_ID.to_string()));
        assert_eq!(result.type_, Some(crate::SendType::File));
        assert_eq!(result.name, Some("encrypted-name".to_string()));
        assert!(result.text.is_none());
        let file = result.file.expect("file variant should be populated");
        assert_eq!(file.id, Some(FILE_ID.to_string()));
        assert_eq!(file.file_name, Some("encrypted-file-name".to_string()));
        assert_eq!(file.size, Some("4200".to_string()));
        assert_eq!(file.size_name, Some("4.2 KB".to_string()));
        assert_eq!(result.expiration_date, None);
        assert_eq!(result.creator_identifier, None);
    }

    #[tokio::test]
    async fn test_access_send_http_error() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sends_api
                .expect_access_using_auth()
                .returning(|_token| {
                    Err(bitwarden_api_api::ApiError::Io(std::io::Error::other(
                        "Simulated error",
                    )))
                })
                .once();
        });

        let result = access_send(&api_client, ACCESS_TOKEN).await;

        assert!(matches!(result.unwrap_err(), AccessSendError::Api(_)));
    }

    // ===== get_file_download_data =====

    #[tokio::test]
    async fn test_get_file_download_data() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sends_api
                .expect_get_send_file_download_data_using_auth()
                .returning(|file_id, token| {
                    assert_eq!(file_id, FILE_ID);
                    assert_eq!(token, ACCESS_TOKEN);
                    Ok(SendFileDownloadDataResponseModel {
                        object: Some("send-fileDownload".to_string()),
                        id: Some(FILE_ID.to_string()),
                        url: Some("https://example.com/download".to_string()),
                    })
                })
                .once();
        });

        let result = get_file_download_data(&api_client, FILE_ID, ACCESS_TOKEN)
            .await
            .unwrap();

        assert_eq!(result.id, Some(FILE_ID.to_string()));
        assert_eq!(result.url, Some("https://example.com/download".to_string()));
    }

    #[tokio::test]
    async fn test_get_file_download_data_http_error() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sends_api
                .expect_get_send_file_download_data_using_auth()
                .returning(|_file_id, _token| {
                    Err(bitwarden_api_api::ApiError::Io(std::io::Error::other(
                        "Simulated error",
                    )))
                })
                .once();
        });

        let result = get_file_download_data(&api_client, FILE_ID, ACCESS_TOKEN).await;

        assert!(matches!(
            result.unwrap_err(),
            GetFileDownloadDataError::Api(_)
        ));
    }

    // ===== SendAccessKey =====

    mod send_access_key {
        //! Tests for [`SendAccessKey`]: URL-fragment key parsing/derivation, password hashing,
        //! and decrypting a [`SendAccessResponse`] into a [`SendAccessView`].

        use bitwarden_core::key_management::create_test_crypto_with_user_key;
        use bitwarden_crypto::{OctetStreamBytes, PrimitiveEncryptable as _, SymmetricCryptoKey};

        use crate::{
            Send, SendAccessDecryptError, SendAccessFileResponse, SendAccessKey,
            SendAccessKeyError, SendAccessResponse, SendAccessTextResponse, SendAuthType,
            SendClient, SendFileView, SendTextView, SendType, SendView,
        };

        /// The url-safe-base64 form of a 16-byte send key, as it appears in the trailing
        /// segment of a send URL fragment. Shared with the tests in `send.rs`.
        const URL_KEY: &str = "Pgui0FK85cNhBGWHAlBHBw";
        const USER_KEY: &str = "bYCsk857hl8QJJtxyRK65tjUrbxKC4aDifJpsml+NIv4W9cVgFvi3qVD+yJTUU2T4UwNKWYtt9pqWf7Q+2WCCg==";

        fn user_key() -> SymmetricCryptoKey {
            USER_KEY
                .to_string()
                .try_into()
                .expect("valid test user key")
        }

        /// Encrypt a [`SendView`] through the authenticated (key-store) path — the exact
        /// path `bw send create` takes — so the receive path can be checked against real
        /// ciphertext rather than a fixture that could drift.
        fn encrypt_send(view: SendView) -> Send {
            create_test_crypto_with_user_key(user_key())
                .encrypt(view)
                .expect("send encrypts")
        }

        fn text_send_view(text: &str, name: &str) -> SendView {
            SendView {
                id: "3d80dd72-2d14-4f26-812c-b0f0018aa144".parse().ok(),
                access_id: Some("ct2APRQtJk-BLLDwAYqhRA".to_owned()),
                name: name.to_owned(),
                notes: None,
                key: Some(URL_KEY.to_owned()),
                new_password: None,
                has_password: false,
                r#type: SendType::Text,
                file: None,
                text: Some(SendTextView {
                    text: Some(text.to_owned()),
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
                auth_type: crate::AuthType::None,
            }
        }

        /// Build the wire-format [`SendAccessResponse`] the server would return for a
        /// text send encrypted by [`encrypt_send`].
        fn text_send_response(send: &Send) -> SendAccessResponse {
            SendAccessResponse {
                id: Some("access-id".to_owned()),
                type_: Some(SendType::Text),
                name: Some(send.name.to_string()),
                text: Some(SendAccessTextResponse {
                    text: send
                        .text
                        .as_ref()
                        .and_then(|t| t.text.as_ref())
                        .map(|t| t.to_string()),
                    hidden: false,
                }),
                file: None,
                data: None,
                expiration_date: None,
                creator_identifier: None,
            }
        }

        /// The load-bearing test for this whole flow: a send encrypted through the
        /// authenticated key-store path must be decryptable by a key derived *only* from the
        /// URL fragment. This pins [`SendAccessKey::from_url_b64`]'s derivation
        /// (`derive_shareable_key(secret, "send", Some("send"))`) byte-for-byte against
        /// [`Send::derive_shareable_key`]. If the two ever drift, every `bw receive`
        /// silently fails to decrypt.
        #[test]
        fn decrypts_ciphertext_produced_by_the_authenticated_path() {
            let send = encrypt_send(text_send_view("This is a test", "Test"));
            let response = text_send_response(&send);

            let access_key = SendAccessKey::from_url_b64(URL_KEY).expect("key parses");
            let view = access_key.decrypt_response(response).expect("decrypts");

            assert_eq!(view.name.as_deref(), Some("Test"));
            assert_eq!(
                view.text.expect("text present").text.as_deref(),
                Some("This is a test")
            );
        }

        #[test]
        fn decrypts_file_name_produced_by_the_authenticated_path() {
            let mut view = text_send_view("unused", "File Send");
            view.r#type = SendType::File;
            view.text = None;
            view.file = Some(SendFileView {
                id: Some("file-id".to_owned()),
                file_name: "secrets.txt".to_owned(),
                size: Some("11".to_owned()),
                size_name: Some("11 B".to_owned()),
            });
            let send = encrypt_send(view);
            let file = send.file.expect("file present");

            let response = SendAccessResponse {
                id: Some("access-id".to_owned()),
                type_: Some(SendType::File),
                name: Some(send.name.to_string()),
                text: None,
                file: Some(SendAccessFileResponse {
                    id: file.id.clone(),
                    file_name: Some(file.file_name.to_string()),
                    size: file.size.clone(),
                    size_name: file.size_name.clone(),
                }),
                data: None,
                expiration_date: None,
                creator_identifier: None,
            };

            let access_key = SendAccessKey::from_url_b64(URL_KEY).expect("key parses");
            let view = access_key.decrypt_response(response).expect("decrypts");

            let decrypted_file = view.file.expect("file present");
            assert_eq!(decrypted_file.file_name.as_deref(), Some("secrets.txt"));
            assert_eq!(decrypted_file.size.as_deref(), Some("11"));
            assert_eq!(decrypted_file.id.as_deref(), Some("file-id"));
            assert_eq!(view.name.as_deref(), Some("File Send"));
        }

        /// A file-send blob is a whole-buffer `EncString`, encrypted under the same stretched
        /// send key. Round-trip it through the authenticated encrypt path (what
        /// `create_file_send` uploads) and the anonymous decrypt path (what `bw receive`
        /// downloads).
        #[test]
        fn decrypt_file_buffer_round_trips_with_the_authenticated_path() {
            let plaintext = b"file send contents".to_vec();

            let crypto = create_test_crypto_with_user_key(user_key());
            let mut ctx = crypto.context();
            let raw_key = bitwarden_encoding::B64Url::try_from(URL_KEY)
                .expect("url key decodes")
                .into_bytes();
            let send_key = Send::derive_shareable_key(&mut ctx, &raw_key).expect("key derives");
            let encrypted = OctetStreamBytes::from(plaintext.clone())
                .encrypt(&mut ctx, send_key)
                .expect("buffer encrypts")
                .to_buffer()
                .expect("buffer serializes");

            let access_key = SendAccessKey::from_url_b64(URL_KEY).expect("key parses");
            let decrypted = access_key
                .decrypt_file_buffer(&encrypted)
                .expect("buffer decrypts");

            assert_eq!(decrypted, plaintext);
        }

        /// `hash_password_b64` and [`SendAuthType::auth_data`] must produce the same
        /// `password_hash_b64`: `auth_data` is what `bw send create --password` stored on the
        /// server, and `hash_password_b64` is what `bw receive` presents to the token grant.
        /// Any divergence turns every password-protected receive into an opaque 400.
        #[test]
        fn hash_password_b64_matches_send_auth_type_auth_data() {
            let raw_key = bitwarden_encoding::B64Url::try_from(URL_KEY)
                .expect("url key decodes")
                .into_bytes();

            let (created_hash, emails) = SendAuthType::Password {
                password: "hunter2".to_owned(),
            }
            .auth_data(&raw_key);
            assert_eq!(emails, None);

            let access_key = SendAccessKey::from_url_b64(URL_KEY).expect("key parses");
            let receive_hash = access_key.hash_password_b64("hunter2");

            assert_eq!(
                created_hash,
                Some(receive_hash),
                "receive's password hash must match the one `bw send create` stored"
            );
        }

        #[test]
        fn hash_password_b64_is_salted_with_the_send_key() {
            // Different sends (different URL keys) must produce different hashes for the
            // same password, otherwise a hash captured from one send would unlock another.
            let a = SendAccessKey::from_url_b64(URL_KEY).expect("key parses");
            let b = SendAccessKey::from_url_b64("AAAAAAAAAAAAAAAAAAAAAA").expect("key parses");
            assert_ne!(
                a.hash_password_b64("hunter2"),
                b.hash_password_b64("hunter2")
            );
        }

        #[test]
        fn from_url_b64_accepts_padded_and_unpadded() {
            // The fragment form is unpadded, but a caller pasting a padded key (or a URL that
            // has been round-tripped through a tool that re-adds padding) should still work.
            let unpadded = SendAccessKey::from_url_b64(URL_KEY).expect("unpadded parses");
            let padded =
                SendAccessKey::from_url_b64(&format!("{URL_KEY}==")).expect("padded parses");
            assert_eq!(
                unpadded.hash_password_b64("p"),
                padded.hash_password_b64("p"),
                "padded and unpadded forms must derive the same key"
            );
        }

        #[test]
        fn from_url_b64_rejects_invalid_base64() {
            assert!(matches!(
                SendAccessKey::from_url_b64("not valid base64!"),
                Err(SendAccessKeyError::InvalidEncoding)
            ));
        }

        #[test]
        fn from_url_b64_rejects_wrong_length() {
            // Too short (8 bytes) and too long (32 bytes) must both be rejected rather than
            // silently truncated or zero-padded into a different key.
            for bad in ["AAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] {
                assert!(
                    matches!(
                        SendAccessKey::from_url_b64(bad),
                        Err(SendAccessKeyError::InvalidLength)
                    ),
                    "expected InvalidLength for {bad:?}"
                );
            }
            assert!(matches!(
                SendAccessKey::from_url_b64(""),
                Err(SendAccessKeyError::InvalidLength)
            ));
        }

        /// A send with no name and no text body must decrypt to a view with `None` fields
        /// rather than erroring — legacy prints whatever it got, and requiring a name would
        /// make otherwise-valid sends unreadable.
        #[test]
        fn decrypt_response_tolerates_absent_fields() {
            let response = SendAccessResponse {
                id: None,
                type_: None,
                name: None,
                text: Some(SendAccessTextResponse {
                    text: None,
                    hidden: true,
                }),
                file: None,
                data: None,
                expiration_date: None,
                creator_identifier: None,
            };

            let access_key = SendAccessKey::from_url_b64(URL_KEY).expect("key parses");
            let view = access_key.decrypt_response(response).expect("decrypts");

            assert_eq!(view.name, None);
            assert_eq!(view.type_, None);
            let text = view.text.expect("text block present");
            assert_eq!(text.text, None);
            assert!(text.hidden);
        }

        #[test]
        fn decrypt_response_errors_on_a_key_that_does_not_match() {
            let send = encrypt_send(text_send_view("This is a test", "Test"));
            let response = SendAccessResponse {
                id: None,
                type_: Some(SendType::Text),
                name: Some(send.name.to_string()),
                text: None,
                file: None,
                data: None,
                expiration_date: None,
                creator_identifier: None,
            };

            // A syntactically valid but wrong URL key must fail loudly, not return garbage.
            let wrong_key =
                SendAccessKey::from_url_b64("AAAAAAAAAAAAAAAAAAAAAA").expect("key parses");
            assert!(wrong_key.decrypt_response(response).is_err());
        }

        #[test]
        fn decrypt_response_errors_on_a_malformed_enc_string() {
            let response = SendAccessResponse {
                id: None,
                type_: Some(SendType::Text),
                name: Some("this is not an EncString".to_owned()),
                text: None,
                file: None,
                data: None,
                expiration_date: None,
                creator_identifier: None,
            };

            let access_key = SendAccessKey::from_url_b64(URL_KEY).expect("key parses");
            assert!(access_key.decrypt_response(response).is_err());
        }

        /// The `--fullObject` JSON dump is a user-facing contract; pin its camelCase wire
        /// shape (including `type` rather than `type_`) so a field rename can't silently
        /// break scripts parsing `bw receive --fullObject`.
        #[test]
        fn send_access_view_serializes_in_camel_case() {
            let view = crate::SendAccessView {
                id: Some("access-id".to_owned()),
                type_: Some(SendType::File),
                name: Some("name".to_owned()),
                text: None,
                file: Some(crate::SendAccessFileView {
                    id: Some("file-id".to_owned()),
                    file_name: Some("secrets.txt".to_owned()),
                    size: Some("11".to_owned()),
                    size_name: Some("11 B".to_owned()),
                }),
                data: None,
                expiration_date: None,
                creator_identifier: None,
            };

            let json = serde_json::to_value(&view).expect("serializes");
            assert_eq!(json["type"], serde_json::json!(1));
            assert_eq!(json["file"]["fileName"], serde_json::json!("secrets.txt"));
            assert_eq!(json["file"]["sizeName"], serde_json::json!("11 B"));
            assert_eq!(json["creatorIdentifier"], serde_json::Value::Null);
        }

        #[test]
        fn decrypt_send_access_success() {
            let send = encrypt_send(text_send_view("This is a test", "Test"));
            let view =
                SendClient::decrypt_send_access(URL_KEY.to_owned(), text_send_response(&send))
                    .expect("decrypts");

            assert_eq!(view.name.as_deref(), Some("Test"));
            assert_eq!(
                view.text.expect("text present").text.as_deref(),
                Some("This is a test")
            );
        }

        #[test]
        fn decrypt_send_access_malformed_b64() {
            let response = SendAccessResponse {
                id: Some("access-id".to_owned()),
                type_: Some(SendType::Text),
                name: Some("Test".to_owned()),
                text: None,
                file: None,
                data: None,
                expiration_date: None,
                creator_identifier: None,
            };

            let result = SendClient::decrypt_send_access("not valid base64!".to_owned(), response);

            assert!(matches!(
                result.unwrap_err(),
                SendAccessDecryptError::Key(SendAccessKeyError::InvalidEncoding)
            ));
        }
    }
}
