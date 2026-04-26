//! Detect and fix corrupt or missing asymmetric key pairs for V1 encryption users.
//!
//! A user may have a corrupt private key that prevents key rotation or V2 encryption upgrade.
//! This module checks whether the user's asymmetric key pair needs regeneration, and if so,
//! generates a new key pair and submits it to the server via
//! `POST /accounts/key-management/regenerate-keys`.

use std::str::FromStr;

use bitwarden_api_api::models::KeyRegenerationRequestModel;
use bitwarden_core::key_management::{
    KeySlotIds, PrivateKeySlotId, SymmetricKeySlotId,
    account_cryptographic_state::WrappedAccountCryptographicState,
};
use bitwarden_crypto::{EncString, PublicKeyEncryptionAlgorithm, SymmetricKeyAlgorithm};
use bitwarden_encoding::B64;
use bitwarden_error::bitwarden_error;
use bitwarden_vault::{Cipher, CipherView};
use thiserror::Error;
use tracing::{error, info, warn};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::UserCryptoManagementClient;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl UserCryptoManagementClient {
    /// Checks whether the user's asymmetric key pair needs regeneration, and if so,
    /// generates a new key pair and submits it to the server.
    ///
    /// Returns `None` if no regeneration was needed, or the updated
    /// [`WrappedAccountCryptographicState`] if regeneration was performed. Callers should
    /// persist the returned state to their local account cryptographic state.
    ///
    /// Requires the client to be unlocked so the current user key is available in memory.
    /// Only applicable to V1 encryption accounts.
    pub async fn regenerate_asymmetric_key_pair_if_needed(
        &self,
    ) -> Result<Option<WrappedAccountCryptographicState>, AsymmetricKeyRegenerationError> {
        let api_client = &self.client.internal.get_api_configurations().api_client;
        internal_regenerate_asymmetric_key_pair_if_needed(self, api_client).await
    }

    /// Checks whether the user's asymmetric key pair needs regeneration.
    ///
    /// Returns `true` if the key pair is missing, corrupt, or doesn't match the public key on
    /// the server. Returns `false` if the key pair is valid or if regeneration is not applicable
    /// (e.g., user key not available, V2 encryption account).
    pub async fn should_regenerate_asymmetric_keys(
        &self,
    ) -> Result<bool, AsymmetricKeyRegenerationError> {
        let api_client = &self.client.internal.get_api_configurations().api_client;
        internal_should_regenerate_asymmetric_keys(self, api_client).await
    }
}

#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum AsymmetricKeyRegenerationError {
    #[error("User key is not available in key store")]
    UserKeyNotAvailable,
    #[error("API call failed during asymmetric key regeneration")]
    ApiError,
    #[error("Cryptographic error during asymmetric key regeneration")]
    CryptoError,
}

pub(crate) async fn internal_regenerate_asymmetric_key_pair_if_needed(
    client: &UserCryptoManagementClient,
    api_client: &bitwarden_api_api::apis::ApiClient,
) -> Result<Option<WrappedAccountCryptographicState>, AsymmetricKeyRegenerationError> {
    let should_regenerate = internal_should_regenerate_asymmetric_keys(client, api_client).await?;
    if !should_regenerate {
        return Ok(None);
    }

    let state = internal_regenerate_asymmetric_key_pair(client, api_client).await?;
    Ok(Some(state))
}

pub(crate) async fn internal_should_regenerate_asymmetric_keys(
    client: &UserCryptoManagementClient,
    api_client: &bitwarden_api_api::apis::ApiClient,
) -> Result<bool, AsymmetricKeyRegenerationError> {
    // Step 1-2: Check user key availability and encryption version
    {
        let key_store = client.client.internal.get_key_store();
        let ctx = key_store.context();

        if !ctx.has_symmetric_key(SymmetricKeySlotId::User) {
            info!("User key not available, skipping asymmetric key regeneration check");
            return Ok(false);
        }

        let algorithm = ctx
            .get_symmetric_key_algorithm(SymmetricKeySlotId::User)
            .map_err(|_| AsymmetricKeyRegenerationError::UserKeyNotAvailable)?;
        if algorithm != SymmetricKeyAlgorithm::Aes256CbcHmac {
            info!("User has non-V1 encryption, asymmetric key regeneration not applicable");
            return Ok(false);
        }
    }

    // Step 3: Fetch key pair from server. A 404 means the user has no keys at all.
    let keys_response = match api_client.accounts_api().get_keys().await {
        Ok(response) => response,
        Err(bitwarden_api_api::apis::Error::ResponseError(e))
            if e.status == reqwest::StatusCode::NOT_FOUND =>
        {
            info!("User has no asymmetric keys (404), regeneration needed");
            return Ok(true);
        }
        Err(e) => {
            error!("Failed to fetch user keys from server: {e:?}");
            return Err(AsymmetricKeyRegenerationError::ApiError);
        }
    };

    let public_key_str = keys_response.public_key.as_deref();
    let private_key_str = keys_response.private_key.as_deref();

    // Step 4: Handle missing key pair, or proceed with verification
    let (public_key_str, private_key_str) = match (public_key_str, private_key_str) {
        (None, None) => {
            info!("User has no asymmetric key pair, regeneration needed");
            return Ok(true);
        }
        (Some(_), None) | (None, Some(_)) => {
            warn!(
                "User has inconsistent asymmetric key pair (one present, one missing), \
                 skipping regeneration"
            );
            return Ok(false);
        }
        (Some(pub_key), Some(priv_key)) => (pub_key, priv_key),
    };

    let encrypted_private_key: EncString = match private_key_str.parse() {
        Ok(enc_string) => enc_string,
        Err(_) => {
            info!("User's private key is not a valid encrypted string, regeneration needed");
            return Ok(true);
        }
    };

    // Step 5: Verify existing key pair using key store
    {
        let key_store = client.client.internal.get_key_store();
        let mut ctx = key_store.context_mut();

        if let Ok(temp_private_key_id) =
            ctx.unwrap_private_key(SymmetricKeySlotId::User, &encrypted_private_key)
        {
            // Private key is decryptable — check if it matches the server's public key
            return match verify_public_key_matches(&ctx, temp_private_key_id, public_key_str) {
                Ok(true) => {
                    info!("User's asymmetric key pair is valid, no regeneration needed");
                    Ok(false)
                }
                Ok(false) => {
                    info!(
                        "User's private key is decryptable but does not match public key, \
                         regeneration needed"
                    );
                    Ok(true)
                }
                Err(_) => {
                    info!(
                        "User's private key is decryptable but not a valid key, \
                         regeneration needed"
                    );
                    Ok(true)
                }
            };
        }
    }

    // Step 6: Private key is undecryptable — validate user key before assuming the private key
    // is corrupt. If the user key itself is wrong (e.g., stale device trust key), regenerating
    // the private key would be incorrect.
    let user_key_valid = can_decrypt_personal_cipher(client, api_client).await;
    if user_key_valid {
        info!(
            "User's private key cannot be decrypted but user key can decrypt vault data, \
             regeneration needed"
        );
        return Ok(true);
    }
    warn!(
        "User's private key cannot be decrypted and user key cannot decrypt vault data, \
         skipping regeneration"
    );
    Ok(false)
}

/// Tries to decrypt a personal cipher to validate the user key. Returns `true` if the user
/// key can decrypt vault data, `false` otherwise (including if no personal ciphers exist).
async fn can_decrypt_personal_cipher(
    client: &UserCryptoManagementClient,
    api_client: &bitwarden_api_api::apis::ApiClient,
) -> bool {
    let Ok(ciphers_response) = api_client.ciphers_api().get_all().await else {
        return false;
    };

    let personal_cipher = ciphers_response
        .data
        .into_iter()
        .flatten()
        .find(|c| c.organization_id.is_none());

    let Some(cipher_response) = personal_cipher else {
        return false;
    };

    let Ok(cipher) = Cipher::try_from(cipher_response) else {
        return false;
    };

    let key_store = client.client.internal.get_key_store();
    key_store.decrypt::<_, _, CipherView>(&cipher).is_ok()
}

/// Compares the public key derived from the private key in the store against the server's public
/// key. Returns `Ok(true)` if they match, `Ok(false)` if they don't, or `Err` if the public key
/// cannot be derived.
fn verify_public_key_matches(
    ctx: &bitwarden_crypto::KeyStoreContext<KeySlotIds>,
    private_key_id: PrivateKeySlotId,
    server_public_key_b64: &str,
) -> Result<bool, AsymmetricKeyRegenerationError> {
    let derived_public_key = ctx
        .get_public_key(private_key_id)
        .map_err(|_| AsymmetricKeyRegenerationError::CryptoError)?;
    let derived_b64 = B64::from(
        derived_public_key
            .to_der()
            .map_err(|_| AsymmetricKeyRegenerationError::CryptoError)?,
    );
    let server_b64 = B64::from_str(server_public_key_b64)
        .map_err(|_| AsymmetricKeyRegenerationError::CryptoError)?;
    Ok(derived_b64.to_string() == server_b64.to_string())
}

pub(crate) async fn internal_regenerate_asymmetric_key_pair(
    client: &UserCryptoManagementClient,
    api_client: &bitwarden_api_api::apis::ApiClient,
) -> Result<WrappedAccountCryptographicState, AsymmetricKeyRegenerationError> {
    // Scope 1: Generate new key pair and extract serialized forms
    let (wrapped_private_key, public_key_b64) = {
        let key_store = client.client.internal.get_key_store();
        let mut ctx = key_store.context_mut();

        let algorithm = ctx
            .get_symmetric_key_algorithm(SymmetricKeySlotId::User)
            .map_err(|_| AsymmetricKeyRegenerationError::UserKeyNotAvailable)?;
        if algorithm != SymmetricKeyAlgorithm::Aes256CbcHmac {
            return Err(AsymmetricKeyRegenerationError::CryptoError);
        }

        let new_private_key_id = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let wrapped = ctx
            .wrap_private_key(SymmetricKeySlotId::User, new_private_key_id)
            .map_err(|_| AsymmetricKeyRegenerationError::CryptoError)?;
        let public_key = ctx
            .get_public_key(new_private_key_id)
            .map_err(|_| AsymmetricKeyRegenerationError::CryptoError)?;
        let public_key_b64 = B64::from(
            public_key
                .to_der()
                .map_err(|_| AsymmetricKeyRegenerationError::CryptoError)?,
        )
        .to_string();

        (wrapped, public_key_b64)
    };

    // POST to server
    info!("Posting regenerated asymmetric key pair to server");
    let request = KeyRegenerationRequestModel {
        user_public_key: Some(public_key_b64),
        user_key_encrypted_user_private_key: Some(wrapped_private_key.to_string()),
    };

    api_client
        .accounts_key_management_api()
        .regenerate_keys(Some(request))
        .await
        .map_err(|e| {
            error!("Failed to post regenerated keys to server: {e:?}");
            AsymmetricKeyRegenerationError::ApiError
        })?;

    // Scope 2: Persist the new private key and return the wrapped state
    let state = {
        let key_store = client.client.internal.get_key_store();
        let mut ctx = key_store.context_mut();

        let temp_private_key_id = ctx
            .unwrap_private_key(SymmetricKeySlotId::User, &wrapped_private_key)
            .map_err(|_| AsymmetricKeyRegenerationError::CryptoError)?;
        ctx.persist_private_key(temp_private_key_id, PrivateKeySlotId::UserPrivateKey)
            .map_err(|_| AsymmetricKeyRegenerationError::CryptoError)?;

        WrappedAccountCryptographicState::get_v1_from_key_store(&ctx)
            .map_err(|_| AsymmetricKeyRegenerationError::CryptoError)?
    };

    info!("Successfully regenerated user asymmetric key pair");
    Ok(state)
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            CipherDetailsResponseModel, CipherDetailsResponseModelListResponseModel,
            KeyRegenerationRequestModel, KeysResponseModel,
        },
    };
    use bitwarden_core::{Client, key_management::SymmetricKeySlotId};
    use bitwarden_crypto::{
        EncString, PrimitiveEncryptable, PublicKeyEncryptionAlgorithm, SymmetricKeyAlgorithm,
    };
    use bitwarden_encoding::B64;

    use super::*;

    /// Creates a client with an unlocked V1 user key.
    fn unlocked_v1_client() -> UserCryptoManagementClient {
        let client = Client::new(None);
        {
            let key_store = client.internal.get_key_store();
            let mut ctx = key_store.context_mut();
            let local_user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            let _ = ctx.persist_symmetric_key(local_user_key, SymmetricKeySlotId::User);
        }
        UserCryptoManagementClient::new(client)
    }

    /// Creates a client with an unlocked V2 user key.
    fn unlocked_v2_client() -> UserCryptoManagementClient {
        let client = Client::new(None);
        {
            let key_store = client.internal.get_key_store();
            let mut ctx = key_store.context_mut();
            let local_user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
            let _ = ctx.persist_symmetric_key(local_user_key, SymmetricKeySlotId::User);
        }
        UserCryptoManagementClient::new(client)
    }

    /// Helper to generate a valid wrapped private key and matching public key B64 string
    /// for a given client.
    fn make_valid_key_pair(client: &UserCryptoManagementClient) -> (String, String) {
        let key_store = client.client.internal.get_key_store();
        let mut ctx = key_store.context_mut();
        let private_key_id = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let wrapped = ctx
            .wrap_private_key(SymmetricKeySlotId::User, private_key_id)
            .unwrap();
        let public_key = ctx.get_public_key(private_key_id).unwrap();
        let public_key_b64 = B64::from(public_key.to_der().unwrap()).to_string();
        (wrapped.to_string(), public_key_b64)
    }

    fn keys_response(public_key: Option<String>, private_key: Option<String>) -> KeysResponseModel {
        KeysResponseModel {
            object: None,
            key: None,
            public_key,
            private_key,
            account_keys: None,
        }
    }

    // ── should_regenerate_asymmetric_keys tests ──

    #[tokio::test]
    async fn test_should_regenerate_no_user_key() {
        let client = UserCryptoManagementClient::new(Client::new(None));

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api.expect_get_keys().never();
        });

        let result = internal_should_regenerate_asymmetric_keys(&client, &api_client).await;
        assert!(!result.unwrap());

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_v2_encryption() {
        let client = unlocked_v2_client();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api.expect_get_keys().never();
        });

        let result = internal_should_regenerate_asymmetric_keys(&client, &api_client).await;
        assert!(!result.unwrap());

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_get_keys_404() {
        let client = unlocked_v1_client();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api.expect_get_keys().once().returning(|| {
                Err(bitwarden_api_api::apis::Error::ResponseError(
                    bitwarden_api_api::apis::ResponseContent {
                        status: reqwest::StatusCode::NOT_FOUND,
                        content: "Not Found".to_string(),
                        entity: None,
                    },
                ))
            });
        });

        let result = internal_should_regenerate_asymmetric_keys(&client, &api_client).await;
        assert!(result.unwrap());

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_no_key_pair_on_server() {
        let client = unlocked_v1_client();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_get_keys()
                .once()
                .returning(|| Ok(keys_response(None, None)));
        });

        let result = internal_should_regenerate_asymmetric_keys(&client, &api_client).await;
        assert!(result.unwrap());

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_inconsistent_key_pair_public_only() {
        let client = unlocked_v1_client();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_get_keys()
                .once()
                .returning(|| Ok(keys_response(Some("some-public-key".to_string()), None)));
        });

        let result = internal_should_regenerate_asymmetric_keys(&client, &api_client).await;
        assert!(!result.unwrap());

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_inconsistent_key_pair_private_only() {
        let client = unlocked_v1_client();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_get_keys()
                .once()
                .returning(|| Ok(keys_response(None, Some("some-private-key".to_string()))));
        });

        let result = internal_should_regenerate_asymmetric_keys(&client, &api_client).await;
        assert!(!result.unwrap());

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_valid_key_pair() {
        let client = unlocked_v1_client();
        let (wrapped_private_key, public_key_b64) = make_valid_key_pair(&client);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_get_keys()
                .once()
                .returning(move || {
                    Ok(keys_response(
                        Some(public_key_b64.clone()),
                        Some(wrapped_private_key.clone()),
                    ))
                });
        });

        let result = internal_should_regenerate_asymmetric_keys(&client, &api_client).await;
        assert!(!result.unwrap());

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_undecryptable_private_key_no_ciphers() {
        // When the private key can't be decrypted and there are no ciphers to validate the
        // user key, we skip regeneration (can't confirm user key is valid).
        let client = unlocked_v1_client();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_get_keys()
                .once()
                .returning(|| {
                    Ok(keys_response(
                        Some("some-public-key".to_string()),
                        Some("2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()),
                    ))
                });
            mock.ciphers_api.expect_get_all().once().returning(|| {
                Ok(CipherDetailsResponseModelListResponseModel {
                    object: None,
                    data: Some(vec![]),
                    continuation_token: None,
                })
            });
        });

        let result = internal_should_regenerate_asymmetric_keys(&client, &api_client).await;
        assert!(!result.unwrap());

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.ciphers_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_undecryptable_private_key_with_valid_user_key() {
        // When the private key can't be decrypted but we CAN decrypt a personal cipher,
        // the user key is valid and the private key is corrupt → regenerate.
        let client = unlocked_v1_client();

        // Encrypt a cipher name with the user key so decryption succeeds
        let encrypted_name = {
            let key_store = client.client.internal.get_key_store();
            let mut ctx = key_store.context_mut();
            let name: EncString = "test cipher"
                .to_string()
                .encrypt(&mut ctx, SymmetricKeySlotId::User)
                .unwrap();
            name.to_string()
        };

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_get_keys()
                .once()
                .returning(|| {
                    Ok(keys_response(
                        Some("some-public-key".to_string()),
                        Some("2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()),
                    ))
                });
            mock.ciphers_api.expect_get_all().once().returning(move || {
                Ok(CipherDetailsResponseModelListResponseModel {
                    object: None,
                    data: Some(vec![CipherDetailsResponseModel {
                        id: Some(uuid::Uuid::new_v4()),
                        name: Some(encrypted_name.clone()),
                        organization_id: None,
                        r#type: Some(bitwarden_api_api::models::CipherType::Login),
                        revision_date: Some("2024-01-01T00:00:00Z".to_string()),
                        creation_date: Some("2024-01-01T00:00:00Z".to_string()),
                        ..CipherDetailsResponseModel::default()
                    }]),
                    continuation_token: None,
                })
            });
        });

        let result = internal_should_regenerate_asymmetric_keys(&client, &api_client).await;
        assert!(result.unwrap());

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.ciphers_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_invalid_enc_string() {
        let client = unlocked_v1_client();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api.expect_get_keys().once().returning(|| {
                Ok(keys_response(
                    Some("some-public-key".to_string()),
                    Some("not-a-valid-enc-string".to_string()),
                ))
            });
        });

        let result = internal_should_regenerate_asymmetric_keys(&client, &api_client).await;
        assert!(result.unwrap());

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_decryptable_but_mismatched() {
        let client = unlocked_v1_client();
        // Generate a valid key pair, but replace the public key with a different one
        let (wrapped_private_key, _) = make_valid_key_pair(&client);
        let wrong_public_key = "AAAAAAAAAA==".to_string();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_get_keys()
                .once()
                .returning(move || {
                    Ok(keys_response(
                        Some(wrong_public_key.clone()),
                        Some(wrapped_private_key.clone()),
                    ))
                });
        });

        let result = internal_should_regenerate_asymmetric_keys(&client, &api_client).await;
        assert!(result.unwrap());

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    // ── regenerate_key_pair tests ──

    #[tokio::test]
    async fn test_regenerate_success() {
        let client = unlocked_v1_client();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_regenerate_keys()
                .once()
                .returning(|body: Option<KeyRegenerationRequestModel>| {
                    let body = body.expect("body should be Some");
                    assert!(
                        body.user_public_key.is_some(),
                        "user_public_key should be present"
                    );
                    let wrapped_key = body
                        .user_key_encrypted_user_private_key
                        .expect("user_key_encrypted_user_private_key should be present");
                    wrapped_key
                        .parse::<EncString>()
                        .expect("should be a valid EncString");
                    Ok(())
                });
        });

        let state = internal_regenerate_asymmetric_key_pair(&client, &api_client)
            .await
            .expect("regeneration should succeed");
        assert!(
            matches!(state, WrappedAccountCryptographicState::V1 { .. }),
            "Should return a V1 state"
        );

        // Verify the private key was persisted to the key store
        {
            let key_store = client.client.internal.get_key_store();
            let ctx = key_store.context();
            assert!(
                ctx.has_private_key(PrivateKeySlotId::UserPrivateKey),
                "UserPrivateKey should be set after regeneration"
            );
        }

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_regenerate_api_failure() {
        let client = unlocked_v1_client();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_regenerate_keys()
                .once()
                .returning(|_body| {
                    Err(bitwarden_api_api::apis::Error::Serde(
                        serde_json::Error::io(std::io::Error::other("API error")),
                    ))
                });
        });

        let result = internal_regenerate_asymmetric_key_pair(&client, &api_client).await;
        assert!(matches!(
            result,
            Err(AsymmetricKeyRegenerationError::ApiError)
        ));

        // Verify the private key was NOT persisted (local state unchanged)
        {
            let key_store = client.client.internal.get_key_store();
            let ctx = key_store.context();
            assert!(
                !ctx.has_private_key(PrivateKeySlotId::UserPrivateKey),
                "UserPrivateKey should NOT be set after API failure"
            );
        }

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    // ── regenerate_asymmetric_key_pair_if_needed tests ──

    #[tokio::test]
    async fn test_regenerate_if_needed_no_regeneration() {
        let client = unlocked_v1_client();
        let (wrapped_private_key, public_key_b64) = make_valid_key_pair(&client);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_get_keys()
                .once()
                .returning(move || {
                    Ok(keys_response(
                        Some(public_key_b64.clone()),
                        Some(wrapped_private_key.clone()),
                    ))
                });
            mock.accounts_key_management_api
                .expect_regenerate_keys()
                .never();
        });

        let result = internal_regenerate_asymmetric_key_pair_if_needed(&client, &api_client).await;
        assert!(result.unwrap().is_none());

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_regenerate_if_needed_performs_regeneration() {
        let client = unlocked_v1_client();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_get_keys()
                .once()
                .returning(|| Ok(keys_response(None, None)));
            mock.accounts_key_management_api
                .expect_regenerate_keys()
                .once()
                .returning(|_body| Ok(()));
        });

        let result = internal_regenerate_asymmetric_key_pair_if_needed(&client, &api_client).await;
        let state = result.unwrap();
        assert!(state.is_some(), "Should return the updated account state");
        assert!(
            matches!(state.unwrap(), WrappedAccountCryptographicState::V1 { .. }),
            "Should be a V1 state"
        );

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.accounts_key_management_api.checkpoint();
        }
    }
}
