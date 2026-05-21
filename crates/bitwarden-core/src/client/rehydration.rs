use std::sync::Arc;

use bitwarden_state::registry::StateRegistry;

use super::Client;
use crate::{
    UserId,
    auth::auth_tokens::TokenHandler,
    client::{
        ClientBuilder, get_host_platform_info,
        persisted_state::{ACCOUNT_CRYPTO_STATE, BASE_URLS, BaseUrls, USER_ID},
    },
    key_management::account_cryptographic_state::WrappedAccountCryptographicState,
};

/// Errors that can occur during client rehydration.
#[derive(Debug, thiserror::Error)]
pub enum RehydrationError {
    /// A required value was not found in the state registry.
    #[error("Required state value not found in registry: {0}")]
    MissingState(String),
    /// An error occurred accessing or updating a setting in the state registry.
    #[error("State access error: {0}")]
    State(#[from] bitwarden_state::SettingsError),
}

/// Data required to populate a [`StateRegistry`] via [`Client::save_to_state`].
///
/// Contains the values the auth flow does not yet persist automatically. Once the auth crate
/// handles persistence directly, this type will be removed.
pub struct SaveStateData {
    /// The authenticated user's ID.
    pub user_id: UserId,
    /// The base API URLs for the user's server.
    pub urls: BaseUrls,
    /// The user's wrapped account cryptographic state.
    pub crypto_state: WrappedAccountCryptographicState,
}

impl Client {
    /// Populates a [`StateRegistry`] with the state required for [`Client::load_from_state`].
    ///
    /// Call this after a successful login to persist the values that the auth flow does not yet
    /// write automatically. Once the auth crate handles persistence directly, this will be removed.
    pub async fn save_to_state(
        data: SaveStateData,
        reg: &StateRegistry,
    ) -> Result<(), RehydrationError> {
        reg.setting(BASE_URLS)
            .map_err(|e| RehydrationError::State(e.into()))?
            .update(data.urls)
            .await
            .map_err(RehydrationError::State)?;
        reg.setting(USER_ID)
            .map_err(|e| RehydrationError::State(e.into()))?
            .update(data.user_id)
            .await
            .map_err(RehydrationError::State)?;
        reg.setting(ACCOUNT_CRYPTO_STATE)
            .map_err(|e| RehydrationError::State(e.into()))?
            .update(data.crypto_state)
            .await
            .map_err(RehydrationError::State)?;
        Ok(())
    }

    /// Reconstruct a locked Client from a populated StateRegistry.
    ///
    /// Does NOT unlock the vault.
    pub async fn load_from_state(
        token_handler: Arc<dyn TokenHandler>,
        registry: StateRegistry,
    ) -> Result<Self, RehydrationError> {
        let base_urls: BaseUrls = registry
            .setting(BASE_URLS)
            .map_err(|e| RehydrationError::State(e.into()))?
            .get()
            .await
            .map_err(RehydrationError::State)?
            .ok_or_else(|| RehydrationError::MissingState("BASE_URLS".to_string()))?;

        let user_id: UserId = registry
            .setting(USER_ID)
            .map_err(|e| RehydrationError::State(e.into()))?
            .get()
            .await
            .map_err(RehydrationError::State)?
            .ok_or_else(|| RehydrationError::MissingState("USER_ID".to_string()))?;

        let platform = get_host_platform_info();
        let settings = crate::ClientSettings {
            identity_url: base_urls.identity_url,
            api_url: base_urls.api_url,
            user_agent: platform.user_agent.clone(),
            device_type: platform.device_type,
            device_identifier: platform.device_identifier.clone(),
            bitwarden_client_version: platform.bitwarden_client_version.clone(),
            bitwarden_package_type: platform.bitwarden_package_type.clone(),
        };

        let client = ClientBuilder::new()
            .with_settings(settings)
            .with_token_handler(token_handler)
            .with_state(registry)
            .build();

        client
            .internal
            .init_user_id(user_id)
            .await
            .expect("user ID cannot already be set on a freshly built client");

        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Once};

    use bitwarden_crypto::{
        KeyStore, PublicKeyEncryptionAlgorithm, SignatureAlgorithm, SymmetricKeyAlgorithm,
    };
    use bitwarden_state::registry::StateRegistry;

    use super::*;
    use crate::{
        DeviceType, HostPlatformInfo, UserId,
        auth::auth_tokens::NoopTokenHandler,
        client::persisted_state::{ACCOUNT_CRYPTO_STATE, BASE_URLS, BaseUrls, USER_ID},
        key_management::{
            KeySlotIds, SecurityState,
            account_cryptographic_state::WrappedAccountCryptographicState,
        },
    };

    static INIT: Once = Once::new();

    fn ensure_platform_info() {
        INIT.call_once(|| {
            crate::init_host_platform_info(HostPlatformInfo {
                user_agent: "rehydration-tests".to_string(),
                device_type: DeviceType::SDK,
                device_identifier: None,
                bitwarden_client_version: None,
                bitwarden_package_type: None,
            });
        });
    }

    fn test_user_id() -> UserId {
        "d5b1fde2-a1e3-4c5b-9e0f-1a2b3c4d5e6f".parse().unwrap()
    }

    fn test_base_urls() -> BaseUrls {
        BaseUrls {
            identity_url: "https://identity.example.com".to_string(),
            api_url: "https://api.example.com".to_string(),
        }
    }

    fn test_crypto_state() -> WrappedAccountCryptographicState {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let private_key_id = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let signing_key_id = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let signed_public_key = ctx
            .make_signed_public_key(private_key_id, signing_key_id)
            .unwrap();
        let security_state = SecurityState::new();
        let signed_security_state = security_state.sign(signing_key_id, &mut ctx).unwrap();
        let wrapped_private = ctx.wrap_private_key(user_key, private_key_id).unwrap();
        let wrapped_signing = ctx.wrap_signing_key(user_key, signing_key_id).unwrap();
        WrappedAccountCryptographicState::V2 {
            private_key: wrapped_private,
            signed_public_key: Some(signed_public_key),
            signing_key: wrapped_signing,
            security_state: signed_security_state,
        }
    }

    fn test_save_data() -> SaveStateData {
        SaveStateData {
            user_id: test_user_id(),
            urls: test_base_urls(),
            crypto_state: test_crypto_state(),
        }
    }

    #[tokio::test]
    async fn save_to_state_writes_all_settings() {
        let reg = StateRegistry::new_with_memory_db();
        let data = test_save_data();
        let expected_user_id = data.user_id;
        let expected_urls_identity = data.urls.identity_url.clone();
        let expected_urls_api = data.urls.api_url.clone();

        Client::save_to_state(data, &reg).await.unwrap();

        // Read back each setting directly from the registry.
        let base_urls: BaseUrls = reg
            .setting(BASE_URLS)
            .unwrap()
            .get()
            .await
            .unwrap()
            .expect("BASE_URLS should be present");
        assert_eq!(base_urls.identity_url, expected_urls_identity);
        assert_eq!(base_urls.api_url, expected_urls_api);

        let user_id: UserId = reg
            .setting(USER_ID)
            .unwrap()
            .get()
            .await
            .unwrap()
            .expect("USER_ID should be present");
        assert_eq!(user_id, expected_user_id);

        let crypto_state: WrappedAccountCryptographicState = reg
            .setting(ACCOUNT_CRYPTO_STATE)
            .unwrap()
            .get()
            .await
            .unwrap()
            .expect("ACCOUNT_CRYPTO_STATE should be present");
        assert!(
            matches!(crypto_state, WrappedAccountCryptographicState::V2 { .. }),
            "Expected V2 crypto state"
        );
    }

    #[tokio::test]
    async fn load_from_state_restores_user_id() {
        ensure_platform_info();

        let reg = StateRegistry::new_with_memory_db();
        let data = test_save_data();
        let expected_user_id = data.user_id;

        Client::save_to_state(data, &reg).await.unwrap();

        let token_handler: Arc<dyn TokenHandler> = Arc::new(NoopTokenHandler);
        let client = Client::load_from_state(token_handler, reg).await.unwrap();

        assert_eq!(
            client.internal.get_user_id(),
            Some(expected_user_id),
            "Restored client should have the saved user ID"
        );
    }

    #[tokio::test]
    async fn load_from_state_missing_base_urls_returns_error() {
        ensure_platform_info();

        let reg = StateRegistry::new_with_memory_db();
        // Registry is empty no settings written.

        let token_handler: Arc<dyn TokenHandler> = Arc::new(NoopTokenHandler);
        let result = Client::load_from_state(token_handler, reg).await;

        match result {
            Err(RehydrationError::MissingState(s)) => {
                assert!(
                    s.contains("BASE_URLS"),
                    "Error message should mention BASE_URLS, got: {s}"
                );
            }
            Err(e) => panic!("Expected MissingState error for BASE_URLS, got: {e:?}"),
            Ok(_) => panic!("Expected MissingState error for BASE_URLS, got Ok"),
        }
    }

    #[tokio::test]
    async fn load_from_state_missing_user_id_returns_error() {
        ensure_platform_info();

        let reg = StateRegistry::new_with_memory_db();
        // Write only BASE_URLS, omit USER_ID.
        reg.setting(BASE_URLS)
            .unwrap()
            .update(test_base_urls())
            .await
            .unwrap();

        let token_handler: Arc<dyn TokenHandler> = Arc::new(NoopTokenHandler);
        let result = Client::load_from_state(token_handler, reg).await;

        match result {
            Err(RehydrationError::MissingState(s)) => {
                assert!(
                    s.contains("USER_ID"),
                    "Error message should mention USER_ID, got: {s}"
                );
            }
            Err(e) => panic!("Expected MissingState error for USER_ID, got: {e:?}"),
            Ok(_) => panic!("Expected MissingState error for USER_ID, got Ok"),
        }
    }
}
