use std::str::FromStr;

use bitwarden_core::key_management::{KeySlotIds, PrivateKeySlotId, SymmetricKeySlotId};
use bitwarden_crypto::{EncString, KeyStore};
use bitwarden_encoding::B64;
use bitwarden_vault::{Cipher, CipherView};
use tracing::{error, info, warn};

use super::KeyPairRegenerationError;

/// Checks whether the user's public key encryption key pair needs regeneration.
///
/// When the private key cannot be decrypted, validates the user key by attempting to
/// decrypt a personal cipher fetched from the API.
pub(super) async fn internal_should_regenerate_public_key_encryption_key_pair(
    key_store: &KeyStore<KeySlotIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
) -> Result<bool, KeyPairRegenerationError> {
    match check_key_pair(key_store, api_client).await? {
        KeyPairCheckResult::Valid => Ok(false),
        KeyPairCheckResult::NeedsRegeneration => Ok(true),
        KeyPairCheckResult::NeedsCipherCheck => {
            is_user_key_valid_from_api(key_store, api_client).await
        }
    }
}

/// Checks whether the user's public key encryption key pair needs regeneration.
///
/// When the private key cannot be decrypted, validates the user key by attempting to
/// decrypt one of the provided ciphers.
pub(super) async fn internal_should_regenerate_public_key_encryption_key_pair_with_ciphers(
    key_store: &KeyStore<KeySlotIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    ciphers: &[Cipher],
) -> Result<bool, KeyPairRegenerationError> {
    match check_key_pair(key_store, api_client).await? {
        KeyPairCheckResult::Valid => Ok(false),
        KeyPairCheckResult::NeedsRegeneration => Ok(true),
        KeyPairCheckResult::NeedsCipherCheck => is_user_key_valid(key_store, ciphers),
    }
}

enum KeyPairCheckResult {
    Valid,
    NeedsRegeneration,
    /// Private key is undecryptable — need to validate user key via cipher decryption
    /// before deciding whether to regenerate.
    NeedsCipherCheck,
}

/// Returns whether the key pair is valid, needs regeneration, or requires a cipher-based
/// user key check to decide.
async fn check_key_pair(
    key_store: &KeyStore<KeySlotIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
) -> Result<KeyPairCheckResult, KeyPairRegenerationError> {
    // Step 1-2: Check user key availability and encryption version
    {
        let ctx = key_store.context();

        if !ctx.has_symmetric_key(SymmetricKeySlotId::User) {
            info!("User key not available, skipping key pair regeneration check");
            return Ok(KeyPairCheckResult::Valid);
        }

        if !ctx
            .is_v1_symmetric_key(SymmetricKeySlotId::User)
            .map_err(|_| KeyPairRegenerationError::UserKeyNotAvailable)?
        {
            info!("User has non-V1 encryption, key pair regeneration not applicable");
            return Ok(KeyPairCheckResult::Valid);
        }
    }

    // Step 3: Fetch key pair from server. A 404 means the user has no keys at all.
    let keys_response = match api_client.accounts_api().get_keys().await {
        Ok(response) => response,
        Err(bitwarden_api_api::apis::Error::ResponseError(e))
            if e.status == reqwest::StatusCode::NOT_FOUND =>
        {
            info!("User has no public key encryption key pair (404), regeneration needed");
            return Ok(KeyPairCheckResult::NeedsRegeneration);
        }
        Err(e) => {
            error!("Failed to fetch user keys from server: {e:?}");
            return Err(KeyPairRegenerationError::ApiError);
        }
    };

    let public_key_str = keys_response.public_key.as_deref();
    let private_key_str = keys_response.private_key.as_deref();

    // Step 4: Handle missing key pair, or proceed with verification
    let (public_key_str, private_key_str) = match (public_key_str, private_key_str) {
        (None, None) => {
            info!("User has no public key encryption key pair, regeneration needed");
            return Ok(KeyPairCheckResult::NeedsRegeneration);
        }
        (Some(_), None) | (None, Some(_)) => {
            info!(
                "User has inconsistent public key encryption key pair (one present, one missing), \
                 regeneration needed"
            );
            return Ok(KeyPairCheckResult::NeedsRegeneration);
        }
        (Some(pub_key), Some(priv_key)) => (pub_key, priv_key),
    };

    let Ok(encrypted_private_key) = private_key_str.parse::<EncString>() else {
        info!("User's private key is not a valid encrypted string, regeneration needed");
        return Ok(KeyPairCheckResult::NeedsRegeneration);
    };

    // Step 5: Verify existing key pair using key store
    {
        let mut ctx = key_store.context_mut();

        if let Ok(temp_private_key_id) =
            ctx.unwrap_private_key(SymmetricKeySlotId::User, &encrypted_private_key)
        {
            return match verify_public_key_matches(&ctx, temp_private_key_id, public_key_str) {
                Ok(true) => {
                    info!("User's public key encryption key pair is valid, no regeneration needed");
                    Ok(KeyPairCheckResult::Valid)
                }
                Ok(false) => {
                    info!(
                        "User's private key is decryptable but does not match public key, \
                         regeneration needed"
                    );
                    Ok(KeyPairCheckResult::NeedsRegeneration)
                }
                Err(_) => {
                    info!(
                        "User's private key is decryptable but public key derivation failed, \
                         regeneration needed"
                    );
                    Ok(KeyPairCheckResult::NeedsRegeneration)
                }
            };
        }
    }

    // Step 6: Private key is undecryptable — need cipher check to validate user key
    Ok(KeyPairCheckResult::NeedsCipherCheck)
}

/// Validates the user key by fetching ciphers from the API and attempting to decrypt a personal
/// one. Returns `Ok(true)` (should regenerate) if the user key is valid, `Ok(false)` otherwise.
async fn is_user_key_valid_from_api(
    key_store: &KeyStore<KeySlotIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
) -> Result<bool, KeyPairRegenerationError> {
    let Ok(ciphers_response) = api_client.ciphers_api().get_all().await else {
        warn!("Failed to fetch ciphers for user key validation, skipping regeneration");
        return Ok(false);
    };

    let personal_cipher = ciphers_response
        .data
        .into_iter()
        .flatten()
        .find(|c| c.organization_id.is_none());

    let Some(cipher_response) = personal_cipher else {
        warn!("No personal ciphers available for user key validation, skipping regeneration");
        return Ok(false);
    };

    let Ok(cipher) = Cipher::try_from(cipher_response) else {
        warn!("Failed to parse cipher for user key validation, skipping regeneration");
        return Ok(false);
    };

    is_user_key_valid(key_store, std::slice::from_ref(&cipher))
}

/// Validates the user key by attempting to decrypt a personal cipher. Returns `Ok(true)`
/// (should regenerate) if the user key is valid, `Ok(false)` otherwise.
fn is_user_key_valid(
    key_store: &KeyStore<KeySlotIds>,
    ciphers: &[Cipher],
) -> Result<bool, KeyPairRegenerationError> {
    let Some(cipher) = ciphers
        .iter()
        .find(|cipher| cipher.organization_id.is_none())
    else {
        warn!("No personal ciphers available for user key validation, skipping regeneration");
        return Ok(false);
    };

    if key_store.decrypt::<_, _, CipherView>(cipher).is_ok() {
        info!(
            "User's private key cannot be decrypted but user key can decrypt vault data, \
             regeneration needed"
        );
        Ok(true)
    } else {
        warn!(
            "User's private key cannot be decrypted and user key cannot decrypt vault data, \
             skipping regeneration"
        );
        Ok(false)
    }
}

/// Verifies that the public key derived from the decrypted private key matches the
/// public key stored on the server.
fn verify_public_key_matches(
    ctx: &bitwarden_crypto::KeyStoreContext<KeySlotIds>,
    private_key_id: PrivateKeySlotId,
    server_public_key_b64: &str,
) -> Result<bool, KeyPairRegenerationError> {
    let derived_public_key = ctx
        .get_public_key(private_key_id)
        .map_err(|_| KeyPairRegenerationError::CryptoError)?;
    let derived_b64 = B64::from(
        derived_public_key
            .to_der()
            .map_err(|_| KeyPairRegenerationError::CryptoError)?,
    );
    let server_b64 =
        B64::from_str(server_public_key_b64).map_err(|_| KeyPairRegenerationError::CryptoError)?;
    Ok(derived_b64.to_string() == server_b64.to_string())
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            CipherDetailsResponseModel, CipherDetailsResponseModelListResponseModel,
            KeysResponseModel,
        },
    };
    use bitwarden_core::{
        Client,
        key_management::{KeySlotIds, SymmetricKeySlotId},
    };
    use bitwarden_crypto::{
        EncString, KeyStore, PrimitiveEncryptable, PublicKeyEncryptionAlgorithm,
        SymmetricKeyAlgorithm,
    };
    use bitwarden_encoding::B64;

    use super::*;
    use crate::UserCryptoManagementClient;

    fn unlocked_v1_key_store() -> KeyStore<KeySlotIds> {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            let _ = ctx.persist_symmetric_key(local_user_key, SymmetricKeySlotId::User);
        }
        store
    }

    fn unlocked_v1_client() -> (UserCryptoManagementClient, KeyStore<KeySlotIds>) {
        let client = Client::new(None);
        {
            let key_store = client.internal.get_key_store();
            let mut ctx = key_store.context_mut();
            let local_user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            let _ = ctx.persist_symmetric_key(local_user_key, SymmetricKeySlotId::User);
        }
        let key_store = client.internal.get_key_store().clone();
        (UserCryptoManagementClient::new(client), key_store)
    }

    fn make_valid_key_pair(key_store: &KeyStore<KeySlotIds>) -> (String, String) {
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

    #[tokio::test]
    async fn test_should_regenerate_no_user_key() {
        let key_store: KeyStore<KeySlotIds> = KeyStore::default();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api.expect_get_keys().never();
        });

        let result =
            internal_should_regenerate_public_key_encryption_key_pair(&key_store, &api_client)
                .await;
        assert!(matches!(result, Ok(false)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_v2_encryption() {
        let key_store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = key_store.context_mut();
            let key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
            let _ = ctx.persist_symmetric_key(key, SymmetricKeySlotId::User);
        }

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api.expect_get_keys().never();
        });

        let result =
            internal_should_regenerate_public_key_encryption_key_pair(&key_store, &api_client)
                .await;
        assert!(matches!(result, Ok(false)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_get_keys_api_error() {
        let key_store = unlocked_v1_key_store();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api.expect_get_keys().once().returning(|| {
                Err(bitwarden_api_api::apis::Error::ResponseError(
                    bitwarden_api_api::apis::ResponseContent {
                        status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                        content: "Internal Server Error".to_string(),
                        entity: None,
                    },
                ))
            });
        });

        let result =
            internal_should_regenerate_public_key_encryption_key_pair(&key_store, &api_client)
                .await;
        assert!(matches!(result, Err(KeyPairRegenerationError::ApiError)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_get_keys_404() {
        let key_store = unlocked_v1_key_store();

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

        let result =
            internal_should_regenerate_public_key_encryption_key_pair(&key_store, &api_client)
                .await;
        assert!(matches!(result, Ok(true)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_no_key_pair_on_server() {
        let key_store = unlocked_v1_key_store();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_get_keys()
                .once()
                .returning(|| Ok(keys_response(None, None)));
        });

        let result =
            internal_should_regenerate_public_key_encryption_key_pair(&key_store, &api_client)
                .await;
        assert!(matches!(result, Ok(true)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_inconsistent_key_pair_public_only() {
        let key_store = unlocked_v1_key_store();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_get_keys()
                .once()
                .returning(|| Ok(keys_response(Some("some-public-key".to_string()), None)));
        });

        let result =
            internal_should_regenerate_public_key_encryption_key_pair(&key_store, &api_client)
                .await;
        assert!(matches!(result, Ok(true)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_inconsistent_key_pair_private_only() {
        let key_store = unlocked_v1_key_store();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_get_keys()
                .once()
                .returning(|| Ok(keys_response(None, Some("some-private-key".to_string()))));
        });

        let result =
            internal_should_regenerate_public_key_encryption_key_pair(&key_store, &api_client)
                .await;
        assert!(matches!(result, Ok(true)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_valid_key_pair() {
        let key_store = unlocked_v1_key_store();
        let (wrapped_private_key, public_key_b64) = make_valid_key_pair(&key_store);

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

        let result =
            internal_should_regenerate_public_key_encryption_key_pair(&key_store, &api_client)
                .await;
        assert!(matches!(result, Ok(false)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_undecryptable_private_key_no_ciphers() {
        let key_store = unlocked_v1_key_store();

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

        let result =
            internal_should_regenerate_public_key_encryption_key_pair(&key_store, &api_client)
                .await;
        assert!(matches!(result, Ok(false)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.ciphers_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_undecryptable_private_key_cipher_fetch_fails() {
        let key_store = unlocked_v1_key_store();

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
                Err(bitwarden_api_api::apis::Error::Serde(
                    serde_json::Error::io(std::io::Error::other("API error")),
                ))
            });
        });

        let result =
            internal_should_regenerate_public_key_encryption_key_pair(&key_store, &api_client)
                .await;
        assert!(matches!(result, Ok(false)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.ciphers_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_undecryptable_private_key_with_valid_user_key() {
        let (_, key_store) = unlocked_v1_client();

        let encrypted_name = {
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

        let result =
            internal_should_regenerate_public_key_encryption_key_pair(&key_store, &api_client)
                .await;
        assert!(matches!(result, Ok(true)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.ciphers_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_invalid_enc_string() {
        let key_store = unlocked_v1_key_store();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api.expect_get_keys().once().returning(|| {
                Ok(keys_response(
                    Some("some-public-key".to_string()),
                    Some("not-a-valid-enc-string".to_string()),
                ))
            });
        });

        let result =
            internal_should_regenerate_public_key_encryption_key_pair(&key_store, &api_client)
                .await;
        assert!(matches!(result, Ok(true)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_decryptable_but_malformed_private_key() {
        let (_, key_store) = unlocked_v1_client();

        let (wrapped_malformed_private_key, encrypted_name) = {
            let mut ctx = key_store.context_mut();
            let malformed_private_key: EncString = "not a valid RSA key"
                .to_string()
                .encrypt(&mut ctx, SymmetricKeySlotId::User)
                .unwrap();
            let name: EncString = "test cipher"
                .to_string()
                .encrypt(&mut ctx, SymmetricKeySlotId::User)
                .unwrap();
            (malformed_private_key.to_string(), name.to_string())
        };

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_get_keys()
                .once()
                .returning(move || {
                    Ok(keys_response(
                        Some("some-public-key".to_string()),
                        Some(wrapped_malformed_private_key.clone()),
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

        let result =
            internal_should_regenerate_public_key_encryption_key_pair(&key_store, &api_client)
                .await;
        assert!(matches!(result, Ok(true)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.ciphers_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_decryptable_but_public_key_mismatched() {
        let key_store = unlocked_v1_key_store();
        let (wrapped_private_key, _) = make_valid_key_pair(&key_store);
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

        let result =
            internal_should_regenerate_public_key_encryption_key_pair(&key_store, &api_client)
                .await;
        assert!(matches!(result, Ok(true)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_decryptable_but_server_public_key_invalid_b64() {
        let key_store = unlocked_v1_key_store();
        let (wrapped_private_key, _) = make_valid_key_pair(&key_store);
        let invalid_b64_public_key = "not valid base64!!!".to_string();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_get_keys()
                .once()
                .returning(move || {
                    Ok(keys_response(
                        Some(invalid_b64_public_key.clone()),
                        Some(wrapped_private_key.clone()),
                    ))
                });
        });

        let result =
            internal_should_regenerate_public_key_encryption_key_pair(&key_store, &api_client)
                .await;
        assert!(matches!(result, Ok(true)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_with_ciphers_undecryptable_private_key_no_personal_ciphers() {
        let key_store = unlocked_v1_key_store();

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
        });

        let result = internal_should_regenerate_public_key_encryption_key_pair_with_ciphers(
            &key_store,
            &api_client,
            &[],
        )
        .await;
        assert!(matches!(result, Ok(false)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_should_regenerate_with_ciphers_undecryptable_private_key_and_undecryptable_cipher()
     {
        let key_store = unlocked_v1_key_store();

        // Create a cipher with a cipher key encrypted under a different user key.
        // This makes Cipher::decrypt fail at decrypt_cipher_key (unwrap_symmetric_key),
        // unlike ciphers without a key field where field-level errors are swallowed.
        let cipher_with_wrong_key = {
            let other_store: KeyStore<KeySlotIds> = KeyStore::default();
            let mut ctx = other_store.context_mut();
            let other_user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            let _ = ctx.persist_symmetric_key(other_user_key, SymmetricKeySlotId::User);
            let cipher_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            let wrapped_cipher_key: EncString = ctx
                .wrap_symmetric_key(SymmetricKeySlotId::User, cipher_key)
                .unwrap();
            let name: EncString = "test cipher"
                .to_string()
                .encrypt(&mut ctx, cipher_key)
                .unwrap();
            Cipher {
                id: None,
                organization_id: None,
                folder_id: None,
                collection_ids: vec![],
                key: Some(wrapped_cipher_key),
                name,
                notes: None,
                r#type: bitwarden_vault::CipherType::Login,
                login: None,
                identity: None,
                card: None,
                secure_note: None,
                ssh_key: None,
                bank_account: None,
                favorite: false,
                reprompt: bitwarden_vault::CipherRepromptType::None,
                organization_use_totp: false,
                edit: false,
                permissions: None,
                view_password: false,
                local_data: None,
                attachments: None,
                fields: None,
                password_history: None,
                creation_date: "2024-01-01T00:00:00Z".parse().unwrap(),
                deleted_date: None,
                revision_date: "2024-01-01T00:00:00Z".parse().unwrap(),
                archived_date: None,
                data: None,
            }
        };

        // Encrypt the private key with a different key so unwrap_private_key fails
        let undecryptable_private_key = {
            let other_store: KeyStore<KeySlotIds> = KeyStore::default();
            let mut ctx = other_store.context_mut();
            let other_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            let _ = ctx.persist_symmetric_key(other_key, SymmetricKeySlotId::User);
            let enc: EncString = "fake private key"
                .to_string()
                .encrypt(&mut ctx, SymmetricKeySlotId::User)
                .unwrap();
            enc.to_string()
        };

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_get_keys()
                .once()
                .returning(move || {
                    Ok(keys_response(
                        Some("some-public-key".to_string()),
                        Some(undecryptable_private_key.clone()),
                    ))
                });
        });

        let result = internal_should_regenerate_public_key_encryption_key_pair_with_ciphers(
            &key_store,
            &api_client,
            &[cipher_with_wrong_key],
        )
        .await;
        assert!(matches!(result, Ok(false)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
        }
    }
}
