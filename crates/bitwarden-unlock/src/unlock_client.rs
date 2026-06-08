//! Client for unlocking a rehydrated Bitwarden SDK client.

use bitwarden_core::Client;
#[cfg(feature = "cli")]
use bitwarden_core::client::persisted_state::{
    ACCOUNT_CRYPTO_STATE, OrganizationSharedKey, SESSION_PROTECTED_USER_KEY,
};

use crate::SessionKey;

/// The unlock factor used to unlock a rehydrated client.
///
/// Currently only session-key unlock is supported. Master password, PIN,
/// biometric, and device-key unlock are explicitly out of scope.
pub enum UnlockMethod {
    /// Unlock using a session key previously obtained from
    /// [`UnlockClient::generate_session_key`].
    SessionKey(SessionKey),
}

/// Errors returned by [`UnlockClient::generate_session_key`] and
/// [`UnlockClient::unlock`].
///
/// Detailed causes are emitted via `tracing::error!` rather than carried in the
/// error type, so callers see a uniform failure shape while operators retain
/// diagnostic visibility through logs.
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    /// An unknown error occurred. See logs for details.
    #[error("An unknown error occurred while unlocking the client")]
    Unknown,
}

/// Client for minting session keys and unlocking the vault with one.
#[derive(Clone)]
pub struct UnlockClient {
    #[cfg_attr(not(feature = "cli"), allow(dead_code))]
    pub(crate) client: Client,
}

impl UnlockClient {
    pub(crate) fn new(client: Client) -> Self {
        Self { client }
    }

    /// Mint a new session key and persist the user key wrapped by it.
    ///
    /// Requires the client to be unlocked (the user key must be present in the
    /// key store). The returned [`SessionKey`] should be stored outside the SDK
    /// by the caller and provided back to [`UnlockClient::unlock`] on the next
    /// rehydrated client.
    #[cfg(feature = "cli")]
    pub async fn generate_session_key(&self) -> Result<SessionKey, UnlockError> {
        use bitwarden_core::key_management::SymmetricKeySlotId;

        let (envelope, session_key) = {
            let key_store = self.client.internal.get_key_store();
            let mut ctx = key_store.context_mut();
            SessionKey::from_context(SymmetricKeySlotId::User, &mut ctx).map_err(|e| {
                tracing::error!("Failed to encrypt user key with session key: {e}");
                UnlockError::Unknown
            })?
        };

        self.client
            .platform()
            .state()
            .setting(SESSION_PROTECTED_USER_KEY)
            .map_err(|e| {
                tracing::error!("Failed to read session_protected_user_key setting handle: {e}");
                UnlockError::Unknown
            })?
            .update(envelope)
            .await
            .map_err(|e| {
                tracing::error!("Failed to save session_protected_user_key: {e}");
                UnlockError::Unknown
            })?;

        Ok(session_key)
    }

    /// Unlock a rehydrated client using the supplied unlock factor.
    ///
    /// Reads [`SESSION_PROTECTED_USER_KEY`] and [`ACCOUNT_CRYPTO_STATE`] from
    /// the state registry, unwraps the user key, initializes the user's crypto
    /// state, and restores any persisted organization keys.
    #[cfg(feature = "cli")]
    pub async fn unlock(&self, unlock: UnlockMethod) -> Result<(), UnlockError> {
        let UnlockMethod::SessionKey(session_key) = unlock;

        let state = self.client.platform().state();

        let session_protected_user_key = state
            .setting(SESSION_PROTECTED_USER_KEY)
            .map_err(|e| {
                tracing::error!("Failed to read session_protected_user_key setting handle: {e}");
                UnlockError::Unknown
            })?
            .get()
            .await
            .map_err(|e| {
                tracing::error!("Failed to read session_protected_user_key: {e}");
                UnlockError::Unknown
            })?
            .ok_or_else(|| {
                tracing::error!("Missing session_protected_user_key in database");
                UnlockError::Unknown
            })?;

        let account_crypto_state = state
            .setting(ACCOUNT_CRYPTO_STATE)
            .map_err(|e| {
                tracing::error!("Failed to read account_crypto_state setting handle: {e}");
                UnlockError::Unknown
            })?
            .get()
            .await
            .map_err(|e| {
                tracing::error!("Failed to read account_crypto_state: {e}");
                UnlockError::Unknown
            })?
            .ok_or_else(|| {
                tracing::error!("Missing account_crypto_state in database");
                UnlockError::Unknown
            })?;

        let decrypted_key = {
            let key_store = self.client.internal.get_key_store();
            let mut ctx = key_store.context_mut();
            let decrypted_key_id = session_key
                .unwrap_to_context(&session_protected_user_key, &mut ctx)
                .map_err(|e| {
                    tracing::error!("Failed to unseal user key with session key: {e}");
                    UnlockError::Unknown
                })?;
            #[allow(deprecated)]
            ctx.dangerous_get_symmetric_key(decrypted_key_id)
                .map_err(|e| {
                    tracing::error!("Failed to read decrypted user key from key store: {e}");
                    UnlockError::Unknown
                })?
                .clone()
        };

        self.client
            .internal
            .initialize_user_crypto_decrypted_key(decrypted_key, account_crypto_state, &None)
            .map_err(|e| {
                tracing::error!("Failed to initialize user crypto with decrypted key: {e}");
                UnlockError::Unknown
            })?;

        let org_keys = state
            .get::<OrganizationSharedKey>()
            .map_err(|e| {
                tracing::error!("Failed to read organization keys repository: {e}");
                UnlockError::Unknown
            })?
            .list()
            .await
            .map_err(|e| {
                tracing::error!("Failed to list organization keys: {e}");
                UnlockError::Unknown
            })?;

        self.client
            .internal
            .initialize_org_crypto(org_keys.into_iter().map(|k| (k.org_id, k.key)).collect())
            .map_err(|e| {
                tracing::error!("Failed to decrypt organization keys: {e}");
                UnlockError::Unknown
            })?;

        Ok(())
    }

    /// Invalidate the persisted session key, locking the vault for future invocations.
    ///
    /// Removes [`SESSION_PROTECTED_USER_KEY`] from the database. Distinct from
    /// `lock()` on long-lived clients (mobile, desktop), which clears keys from memory: the
    /// CLI process exits between invocations, so locking must delete the persisted session
    /// key rather than mutate in-memory state.
    #[cfg(feature = "cli")]
    pub async fn invalidate_session_key(&self) -> Result<(), bitwarden_state::SettingsError> {
        self.client
            .platform()
            .state()
            .setting(SESSION_PROTECTED_USER_KEY)?
            .delete()
            .await
    }
}

/// Extension trait to add the unlock client to the main Bitwarden SDK client.
pub trait UnlockClientExt {
    /// Get the unlock client.
    fn unlock(&self) -> UnlockClient;
}

impl UnlockClientExt for Client {
    fn unlock(&self) -> UnlockClient {
        UnlockClient::new(self.clone())
    }
}

#[cfg(all(test, feature = "cli"))]
mod tests {
    // Clippy's automatic test-code exemption for `unwrap_used` keys off a bare
    // `#[cfg(test)]` and doesn't trigger when extra cfg predicates are present.
    #![allow(clippy::unwrap_used)]

    use std::sync::{Arc, Once};

    use bitwarden_core::{
        Client, DeviceType, HostPlatformInfo, SaveStateData, UserId,
        auth::auth_tokens::{NoopTokenHandler, TokenHandler},
        client::persisted_state::{BASE_URLS, BaseUrls, SESSION_PROTECTED_USER_KEY, USER_ID},
        key_management::{
            KeySlotIds, SecurityState, SymmetricKeySlotId,
            account_cryptographic_state::WrappedAccountCryptographicState,
        },
    };
    use bitwarden_crypto::{
        KeyStore, PublicKeyEncryptionAlgorithm, SignatureAlgorithm, SymmetricCryptoKey,
        SymmetricKeyAlgorithm,
        safe::{SymmetricKeyEnvelope, SymmetricKeyEnvelopeNamespace},
    };
    use bitwarden_state::registry::StateRegistry;

    use super::*;

    static INIT: Once = Once::new();

    fn ensure_platform_info() {
        INIT.call_once(|| {
            bitwarden_core::init_host_platform_info(HostPlatformInfo {
                user_agent: "unlock-tests".to_string(),
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

    fn is_unlocked(client: &Client) -> bool {
        client
            .internal
            .get_key_store()
            .context()
            .has_symmetric_key(SymmetricKeySlotId::User)
    }

    fn user_key_base64(client: &Client) -> String {
        let key_store = client.internal.get_key_store();
        let ctx = key_store.context();
        #[allow(deprecated)]
        ctx.dangerous_get_symmetric_key(SymmetricKeySlotId::User)
            .unwrap()
            .to_base64()
            .to_string()
    }

    /// Mint a fresh `(user_key, account_crypto_state)` pair where the wrapped
    /// state was sealed with `user_key`.
    fn make_test_user_crypto() -> (SymmetricCryptoKey, WrappedAccountCryptographicState) {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let user_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let private_key_id = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let signing_key_id = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let signed_public_key = ctx
            .make_signed_public_key(private_key_id, signing_key_id)
            .unwrap();
        let security_state = SecurityState::new();
        let signed_security_state = security_state.sign(signing_key_id, &mut ctx).unwrap();
        let wrapped_private = ctx.wrap_private_key(user_key_id, private_key_id).unwrap();
        let wrapped_signing = ctx.wrap_signing_key(user_key_id, signing_key_id).unwrap();
        #[allow(deprecated)]
        let user_key = ctx
            .dangerous_get_symmetric_key(user_key_id)
            .unwrap()
            .clone();
        (
            user_key,
            WrappedAccountCryptographicState::V2 {
                private_key: wrapped_private,
                signed_public_key: Some(signed_public_key),
                signing_key: wrapped_signing,
                security_state: signed_security_state,
            },
        )
    }

    /// Wrap `user_key` with a freshly generated session key, returning the
    /// envelope and the session key.
    fn seal_with_new_session_key(
        user_key: &SymmetricCryptoKey,
    ) -> (SymmetricKeyEnvelope, SessionKey) {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let user_key_id = ctx.add_local_symmetric_key(user_key.clone());
        let session_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let envelope = SymmetricKeyEnvelope::seal(
            user_key_id,
            session_key_id,
            SymmetricKeyEnvelopeNamespace::SessionKey,
            &ctx,
        )
        .unwrap();
        #[allow(deprecated)]
        let session_key = ctx
            .dangerous_get_symmetric_key(session_key_id)
            .unwrap()
            .clone();
        (envelope, SessionKey(session_key))
    }

    async fn populate_registry_for_unlock(
        envelope: SymmetricKeyEnvelope,
        crypto_state: WrappedAccountCryptographicState,
    ) -> StateRegistry {
        let reg = StateRegistry::new_with_memory_db();
        reg.setting(SESSION_PROTECTED_USER_KEY)
            .unwrap()
            .update(envelope)
            .await
            .unwrap();
        Client::save_to_state(
            SaveStateData {
                user_id: test_user_id(),
                urls: test_base_urls(),
                crypto_state,
            },
            &reg,
        )
        .await
        .unwrap();
        reg
    }

    #[tokio::test]
    async fn generate_session_key_persists_envelope() {
        ensure_platform_info();
        let (user_key, crypto_state) = make_test_user_crypto();

        let reg = StateRegistry::new_with_memory_db();
        Client::save_to_state(
            SaveStateData {
                user_id: test_user_id(),
                urls: test_base_urls(),
                crypto_state: crypto_state.clone(),
            },
            &reg,
        )
        .await
        .unwrap();

        let token_handler: Arc<dyn TokenHandler> = Arc::new(NoopTokenHandler);
        let client = Client::load_from_state(token_handler, reg).await.unwrap();
        client
            .internal
            .initialize_user_crypto_decrypted_key(user_key, crypto_state, &None)
            .unwrap();

        let _session_key = client.unlock().generate_session_key().await.unwrap();

        let envelope: Option<SymmetricKeyEnvelope> = client
            .platform()
            .state()
            .setting(SESSION_PROTECTED_USER_KEY)
            .unwrap()
            .get()
            .await
            .unwrap();
        assert!(
            envelope.is_some(),
            "SESSION_PROTECTED_USER_KEY should be persisted after generate_session_key"
        );
    }

    #[tokio::test]
    async fn unlock_with_session_key_restores_user_key() {
        ensure_platform_info();
        let (user_key, crypto_state) = make_test_user_crypto();
        let expected_user_key = user_key.to_base64().to_string();
        let (envelope, session_key) = seal_with_new_session_key(&user_key);

        let reg = populate_registry_for_unlock(envelope, crypto_state).await;
        let token_handler: Arc<dyn TokenHandler> = Arc::new(NoopTokenHandler);
        let client = Client::load_from_state(token_handler, reg).await.unwrap();
        assert!(
            !is_unlocked(&client),
            "Rehydrated client should start locked"
        );

        client
            .unlock()
            .unlock(UnlockMethod::SessionKey(session_key))
            .await
            .unwrap();

        assert!(is_unlocked(&client));
        assert_eq!(
            user_key_base64(&client),
            expected_user_key,
            "Unlocked user key should match the original"
        );
    }

    #[tokio::test]
    async fn unlock_missing_session_protected_user_key_returns_unknown() {
        ensure_platform_info();
        let (user_key, crypto_state) = make_test_user_crypto();
        let (_, session_key) = seal_with_new_session_key(&user_key);

        let reg = StateRegistry::new_with_memory_db();
        Client::save_to_state(
            SaveStateData {
                user_id: test_user_id(),
                urls: test_base_urls(),
                crypto_state,
            },
            &reg,
        )
        .await
        .unwrap();
        let token_handler: Arc<dyn TokenHandler> = Arc::new(NoopTokenHandler);
        let client = Client::load_from_state(token_handler, reg).await.unwrap();

        let result = client
            .unlock()
            .unlock(UnlockMethod::SessionKey(session_key))
            .await;
        assert!(matches!(result, Err(UnlockError::Unknown)));
    }

    #[tokio::test]
    async fn unlock_missing_account_crypto_state_returns_unknown() {
        ensure_platform_info();
        let (user_key, _crypto_state) = make_test_user_crypto();
        let (envelope, session_key) = seal_with_new_session_key(&user_key);

        let reg = StateRegistry::new_with_memory_db();
        reg.setting(BASE_URLS)
            .unwrap()
            .update(test_base_urls())
            .await
            .unwrap();
        reg.setting(USER_ID)
            .unwrap()
            .update(test_user_id())
            .await
            .unwrap();
        reg.setting(SESSION_PROTECTED_USER_KEY)
            .unwrap()
            .update(envelope)
            .await
            .unwrap();
        let token_handler: Arc<dyn TokenHandler> = Arc::new(NoopTokenHandler);
        let client = Client::load_from_state(token_handler, reg).await.unwrap();

        let result = client
            .unlock()
            .unlock(UnlockMethod::SessionKey(session_key))
            .await;
        assert!(matches!(result, Err(UnlockError::Unknown)));
    }

    #[tokio::test]
    async fn unlock_with_wrong_session_key_returns_unknown() {
        ensure_platform_info();
        let (user_key, crypto_state) = make_test_user_crypto();
        let (envelope, _real_session_key) = seal_with_new_session_key(&user_key);

        let reg = populate_registry_for_unlock(envelope, crypto_state).await;
        let token_handler: Arc<dyn TokenHandler> = Arc::new(NoopTokenHandler);
        let client = Client::load_from_state(token_handler, reg).await.unwrap();

        let wrong_key = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        let result = client
            .unlock()
            .unlock(UnlockMethod::SessionKey(SessionKey(wrong_key)))
            .await;
        assert!(matches!(result, Err(UnlockError::Unknown)));
    }
}
