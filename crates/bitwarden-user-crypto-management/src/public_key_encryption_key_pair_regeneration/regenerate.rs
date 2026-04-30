use bitwarden_api_api::models::KeyRegenerationRequestModel;
use bitwarden_core::key_management::{
    KeySlotIds, PrivateKeySlotId, SymmetricKeySlotId,
    account_cryptographic_state::WrappedAccountCryptographicState,
};
use bitwarden_crypto::{KeyStore, PublicKeyEncryptionAlgorithm};
use bitwarden_encoding::B64;
use tracing::{error, info};

use super::KeyPairRegenerationError;

/// Generates a new public key encryption key pair, submits it to the server, and
/// persists the new private key in the key store.
pub(super) async fn internal_regenerate_public_key_encryption_key_pair(
    key_store: &KeyStore<KeySlotIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
) -> Result<WrappedAccountCryptographicState, KeyPairRegenerationError> {
    let (wrapped_private_key, public_key_b64) = {
        let mut ctx = key_store.context_mut();

        if !ctx
            .is_v1_symmetric_key(SymmetricKeySlotId::User)
            .map_err(|_| KeyPairRegenerationError::UserKeyNotAvailable)?
        {
            return Err(KeyPairRegenerationError::CryptoError);
        }

        let new_private_key_id = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let wrapped = ctx
            .wrap_private_key(SymmetricKeySlotId::User, new_private_key_id)
            .map_err(|_| KeyPairRegenerationError::CryptoError)?;
        let public_key = ctx
            .get_public_key(new_private_key_id)
            .map_err(|_| KeyPairRegenerationError::CryptoError)?;
        let public_key_b64 = B64::from(
            public_key
                .to_der()
                .map_err(|_| KeyPairRegenerationError::CryptoError)?,
        )
        .to_string();

        (wrapped, public_key_b64)
    };

    info!("Posting regenerated public key encryption key pair to server");
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
            KeyPairRegenerationError::ApiError
        })?;

    let state = {
        let mut ctx = key_store.context_mut();

        let temp_private_key_id = ctx
            .unwrap_private_key(SymmetricKeySlotId::User, &wrapped_private_key)
            .map_err(|_| KeyPairRegenerationError::CryptoError)?;
        ctx.persist_private_key(temp_private_key_id, PrivateKeySlotId::UserPrivateKey)
            .map_err(|_| KeyPairRegenerationError::CryptoError)?;

        WrappedAccountCryptographicState::get_v1_from_key_store(&ctx)
            .map_err(|_| KeyPairRegenerationError::CryptoError)?
    };

    info!("Successfully regenerated user public key encryption key pair");
    Ok(state)
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::KeyRegenerationRequestModel};
    use bitwarden_core::{
        Client,
        key_management::{KeySlotIds, PrivateKeySlotId, SymmetricKeySlotId},
    };
    use bitwarden_crypto::{
        EncString, KeyStore, PublicKeyEncryptionAlgorithm, SymmetricKeyAlgorithm,
    };
    use bitwarden_encoding::B64;

    use super::*;
    use crate::UserCryptoManagementClient;

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

    fn unlocked_v1_key_store() -> KeyStore<KeySlotIds> {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            let _ = ctx.persist_symmetric_key(local_user_key, SymmetricKeySlotId::User);
        }
        store
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

    fn keys_response(
        public_key: Option<String>,
        private_key: Option<String>,
    ) -> bitwarden_api_api::models::KeysResponseModel {
        bitwarden_api_api::models::KeysResponseModel {
            object: None,
            key: None,
            public_key,
            private_key,
            account_keys: None,
        }
    }

    // ── regenerate_key_pair tests ──

    #[tokio::test]
    async fn test_regenerate_success() {
        let (_, key_store) = unlocked_v1_client();

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

        let state = internal_regenerate_public_key_encryption_key_pair(&key_store, &api_client)
            .await
            .expect("regeneration should succeed");
        assert!(
            matches!(state, WrappedAccountCryptographicState::V1 { .. }),
            "Should return a V1 state"
        );

        {
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
        let (_, key_store) = unlocked_v1_client();

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

        let result =
            internal_regenerate_public_key_encryption_key_pair(&key_store, &api_client).await;
        assert!(matches!(result, Err(KeyPairRegenerationError::ApiError)));

        {
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

    #[tokio::test]
    async fn test_regenerate_no_user_key() {
        let key_store: KeyStore<KeySlotIds> = KeyStore::default();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_regenerate_keys()
                .never();
        });

        let result =
            internal_regenerate_public_key_encryption_key_pair(&key_store, &api_client).await;
        assert!(matches!(
            result,
            Err(KeyPairRegenerationError::UserKeyNotAvailable)
        ));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_regenerate_v2_user_key() {
        let key_store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = key_store.context_mut();
            let key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
            let _ = ctx.persist_symmetric_key(key, SymmetricKeySlotId::User);
        }

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_regenerate_keys()
                .never();
        });

        let result =
            internal_regenerate_public_key_encryption_key_pair(&key_store, &api_client).await;
        assert!(matches!(result, Err(KeyPairRegenerationError::CryptoError)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    // ── regenerate_if_needed tests ──

    #[tokio::test]
    async fn test_regenerate_if_needed_no_regeneration() {
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
            mock.accounts_key_management_api
                .expect_regenerate_keys()
                .never();
        });

        let should = crate::public_key_encryption_key_pair_regeneration::should_regenerate::internal_should_regenerate_public_key_encryption_key_pair_with_ciphers(
            &key_store, &api_client, &[],
        )
        .await
        .unwrap();
        assert!(!should);

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_regenerate_if_needed_performs_regeneration() {
        let key_store = unlocked_v1_key_store();

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

        let should = crate::public_key_encryption_key_pair_regeneration::should_regenerate::internal_should_regenerate_public_key_encryption_key_pair_with_ciphers(
            &key_store, &api_client, &[],
        )
        .await
        .unwrap();
        assert!(should);

        let state = internal_regenerate_public_key_encryption_key_pair(&key_store, &api_client)
            .await
            .unwrap();
        assert!(
            matches!(state, WrappedAccountCryptographicState::V1 { .. }),
            "Should be a V1 state"
        );

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.accounts_key_management_api.checkpoint();
        }
    }
}
