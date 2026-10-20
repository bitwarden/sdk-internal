//! Client for unlocking a rehydrated Bitwarden SDK client.

#[cfg(feature = "cli")]
use bitwarden_core::client::persisted_state::{
    ACCOUNT_CRYPTO_STATE, OrganizationSharedKey, SESSION_PROTECTED_USER_KEY,
};
use bitwarden_core::{
    Client,
    client::encryption_settings::EncryptionSettingsError,
    key_management::{SymmetricKeySlotId, crypto::InitUserCryptoRequest},
};
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};

#[cfg(feature = "cli")]
use crate::SessionKey;

/// The unlock factor passed to [`UnlockClient::unlock`].
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
// `SessionKey` has no UniFFI representation, so the enum is a UniFFI type only when the CLI-only
// session-key variant is compiled out.
#[cfg_attr(all(feature = "uniffi", not(feature = "cli")), derive(uniffi::Enum))]
#[bitwarden_ffi::wasm_record]
#[allow(clippy::large_enum_variant)]
pub enum UnlockMethod {
    /// Unlock by initializing the user's crypto state from an [`InitUserCryptoRequest`], as
    /// [`CryptoClient::initialize_user_crypto`](bitwarden_core::key_management::CryptoClient::initialize_user_crypto)
    /// does.
    Legacy(InitUserCryptoRequest),
    /// Unlock using a session key previously obtained from
    /// [`UnlockClient::generate_session_key`].
    ///
    /// Only the CLI unlocks with a session key, so this variant is not part of the WASM or UniFFI
    /// surface. `serde(skip)` keeps it out of the generated TypeScript type.
    #[cfg(feature = "cli")]
    #[serde(skip)]
    SessionKey(SessionKey),
}

/// Errors returned by [`UnlockClient::generate_session_key`] and
/// [`UnlockClient::unlock`].
#[bitwarden_error(flat)]
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    /// The client already holds a user key. Nothing was changed.
    #[error("The client is already unlocked")]
    AlreadyUnlocked,
    /// Initializing the user's crypto state failed, for example because of a wrong PIN or
    /// password.
    #[error(transparent)]
    EncryptionSettings(#[from] EncryptionSettingsError),
    /// An unknown error occurred while handling a session key. The detailed cause is emitted via
    /// `tracing::error!` rather than carried in the error, so callers see a uniform failure shape
    /// while operators retain diagnostic visibility through logs.
    #[error("An unknown error occurred while unlocking the client")]
    Unknown,
}

/// Client for unlocking and locking the vault in memory, and for minting session keys and
/// unlocking the vault with one.
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[bitwarden_ffi::wasm_object]
pub struct UnlockClient {
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

    /// Whether the key store holds the user key.
    fn has_user_key(&self) -> bool {
        self.client
            .internal
            .get_key_store()
            .context()
            .has_symmetric_key(SymmetricKeySlotId::User)
    }

    /// Unlock a rehydrated client with a session key.
    ///
    /// Reads [`SESSION_PROTECTED_USER_KEY`] and [`ACCOUNT_CRYPTO_STATE`] from
    /// the state registry, unwraps the user key, initializes the user's crypto
    /// state, and restores any persisted organization keys.
    #[cfg(feature = "cli")]
    async fn unlock_with_session_key(&self, session_key: SessionKey) -> Result<(), UnlockError> {
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

    /// Delete the persisted session key, so later CLI invocations can no longer unlock with it.
    ///
    /// Removes [`SESSION_PROTECTED_USER_KEY`] from the database. This is how the CLI locks: each
    /// command runs in a new process, so there are no in-memory keys to clear. Long-lived clients
    /// lock with [`UnlockClient::lock`] instead.
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

#[bitwarden_ffi::wasm_export]
// `UnlockMethod` is a UniFFI type only without the `cli` feature, see its definition.
#[cfg_attr(
    all(feature = "uniffi", not(feature = "cli")),
    uniffi::export(async_runtime = "tokio")
)]
impl UnlockClient {
    /// Unlock the client with the supplied unlock factor.
    ///
    /// [`UnlockMethod::Legacy`] initializes the user's crypto state from the request, as
    /// `CryptoClient::initialize_user_crypto` does, and returns its errors as
    /// [`UnlockError::EncryptionSettings`].
    ///
    /// If the client is already unlocked, this returns [`UnlockError::AlreadyUnlocked`] before
    /// doing any work and leaves the client's keys untouched. The check only looks at whether a
    /// user key is present: it does not check which key the client holds, or whether it belongs
    /// to the user or account in the request.
    pub async fn unlock(&self, method: UnlockMethod) -> Result<(), UnlockError> {
        if self.has_user_key() {
            return Err(UnlockError::AlreadyUnlocked);
        }

        match method {
            UnlockMethod::Legacy(request) => {
                Ok(self.client.crypto().initialize_user_crypto(request).await?)
            }
            #[cfg(feature = "cli")]
            UnlockMethod::SessionKey(session_key) => {
                self.unlock_with_session_key(session_key).await
            }
        }
    }
}

#[bitwarden_ffi::wasm_export]
#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
impl UnlockClient {
    /// Clear the in-memory user and organization keys, retaining the client instance so that a
    /// later [`UnlockClient::unlock`] re-unlocks it.
    ///
    /// On WASM, unlocking also copies the user key into client-held state through the
    /// key-management state bridge, so locking clears it there as well. The in-memory keys are
    /// cleared first, so the SDK is locked even if the state bridge call fails.
    // The signature is part of the UniFFI and wasm public surface; only the WASM build awaits.
    #[cfg_attr(not(feature = "wasm"), allow(clippy::unused_async))]
    pub async fn lock(&self) {
        self.client.internal.get_key_store().clear();

        // Same gate as `copy_user_key_to_state`, which copies the unlocked user key to the state
        // bridge only on WASM. Clients on other bindings keep their SDK instance for the whole
        // unlocked session, so unlocking never puts the key there for them.
        #[cfg(feature = "wasm")]
        {
            let bridge = self.client.km_state_bridge();
            if bridge.is_bridge_registered() {
                bridge.clear_user_key().await;
            }
        }
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

#[cfg(test)]
mod lock_tests {
    use bitwarden_core::{
        Client, UserId,
        key_management::{
            KeySlotIds, SymmetricKeySlotId,
            account_cryptographic_state::WrappedAccountCryptographicState,
            crypto::{InitUserCryptoMethod, InitUserCryptoRequest},
        },
    };
    use bitwarden_crypto::{
        CryptoError, Decryptable, EncString, Kdf, KeyStore, PrimitiveEncryptable,
        SymmetricCryptoKey,
    };

    use super::*;

    const PLAINTEXT: &str = "secret";

    /// Mint a fresh `(user_key, account_crypto_state)` pair where the wrapped
    /// state was sealed with `user_key`.
    fn make_test_user_crypto() -> (SymmetricCryptoKey, WrappedAccountCryptographicState) {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (user_key_id, crypto_state) = WrappedAccountCryptographicState::make(&mut ctx).unwrap();
        #[allow(deprecated)]
        let user_key = ctx
            .dangerous_get_symmetric_key(user_key_id)
            .unwrap()
            .clone();
        (user_key, crypto_state)
    }

    fn init_request(
        user_key: &SymmetricCryptoKey,
        crypto_state: &WrappedAccountCryptographicState,
    ) -> InitUserCryptoRequest {
        InitUserCryptoRequest {
            user_id: Some(
                "d5b1fde2-a1e3-4c5b-9e0f-1a2b3c4d5e6f"
                    .parse::<UserId>()
                    .unwrap(),
            ),
            kdf_params: Kdf::default_pbkdf2(),
            email: "test@bitwarden.com".to_string(),
            account_cryptographic_state: crypto_state.clone(),
            method: InitUserCryptoMethod::DecryptedKey {
                decrypted_user_key: user_key.to_base64().to_string(),
            },
            upgrade_token: None,
        }
    }

    /// Build a client unlocked with a fresh user key, and a value encrypted with that key.
    async fn unlocked_client() -> (Client, InitUserCryptoRequest, EncString) {
        let (user_key, crypto_state) = make_test_user_crypto();
        let client = Client::new_test(None);
        client
            .crypto()
            .initialize_user_crypto(init_request(&user_key, &crypto_state))
            .await
            .unwrap();

        let encrypted = {
            let key_store = client.internal.get_key_store();
            let mut ctx = key_store.context();
            PLAINTEXT
                .encrypt(&mut ctx, SymmetricKeySlotId::User)
                .unwrap()
        };

        (client, init_request(&user_key, &crypto_state), encrypted)
    }

    fn decrypt_with_user_key(
        client: &Client,
        encrypted: &EncString,
    ) -> Result<String, CryptoError> {
        let key_store = client.internal.get_key_store();
        let mut ctx = key_store.context();
        encrypted.decrypt(&mut ctx, SymmetricKeySlotId::User)
    }

    #[tokio::test]
    async fn lock_makes_crypto_operations_fail_as_uninitialized() {
        let (client, _, encrypted) = unlocked_client().await;

        client.unlock().lock().await;

        let result = decrypt_with_user_key(&client, &encrypted);
        assert!(
            matches!(result, Err(CryptoError::MissingKeyId(_))),
            "Decrypting after lock should fail with a missing key, got {result:?}"
        );
    }

    #[tokio::test]
    async fn initialize_user_crypto_after_lock_reunlocks_same_instance() {
        let (client, request, encrypted) = unlocked_client().await;

        client.unlock().lock().await;
        client
            .crypto()
            .initialize_user_crypto(request)
            .await
            .unwrap();

        assert_eq!(
            decrypt_with_user_key(&client, &encrypted).unwrap(),
            PLAINTEXT
        );
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn lock_clears_user_key_from_state_bridge() {
        use bitwarden_core::key_management::state_bridge::test_support::InMemoryStateBridge;

        let (user_key, crypto_state) = make_test_user_crypto();
        let client = Client::new_test(None);
        let bridge = client.km_state_bridge();
        bridge.register_bridge(Box::new(InMemoryStateBridge::default()));
        client
            .crypto()
            .initialize_user_crypto(init_request(&user_key, &crypto_state))
            .await
            .unwrap();
        assert!(
            bridge.get_user_key().await.is_some(),
            "Unlocking should copy the user key into the state bridge"
        );

        client.unlock().lock().await;

        assert!(
            bridge.get_user_key().await.is_none(),
            "Locking should clear the user key from the state bridge"
        );
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

    #[tokio::test]
    async fn legacy_unlock_unlocks_fresh_client() {
        let (user_key, crypto_state) = make_test_user_crypto();
        let client = Client::new_test(None);

        client
            .unlock()
            .unlock(UnlockMethod::Legacy(init_request(&user_key, &crypto_state)))
            .await
            .unwrap();

        assert_eq!(
            user_key_base64(&client),
            user_key.to_base64().to_string(),
            "Unlocking should load the request's user key into the key store"
        );
    }

    #[tokio::test]
    async fn unlock_on_unlocked_client_returns_already_unlocked_and_keeps_user_key() {
        let (client, _, encrypted) = unlocked_client().await;
        let user_key_before = user_key_base64(&client);

        // A request for a different user key: the check must not depend on the request.
        let (other_user_key, other_crypto_state) = make_test_user_crypto();
        let result = client
            .unlock()
            .unlock(UnlockMethod::Legacy(init_request(
                &other_user_key,
                &other_crypto_state,
            )))
            .await;

        assert!(
            matches!(result, Err(UnlockError::AlreadyUnlocked)),
            "Unlocking an unlocked client should return AlreadyUnlocked, got {result:?}"
        );
        assert_eq!(user_key_base64(&client), user_key_before);
        assert_eq!(
            decrypt_with_user_key(&client, &encrypted).unwrap(),
            PLAINTEXT
        );
    }

    #[tokio::test]
    async fn unlock_after_lock_reunlocks_same_instance() {
        let (client, request, encrypted) = unlocked_client().await;

        client.unlock().lock().await;
        client
            .unlock()
            .unlock(UnlockMethod::Legacy(request))
            .await
            .unwrap();

        assert_eq!(
            decrypt_with_user_key(&client, &encrypted).unwrap(),
            PLAINTEXT
        );
    }

    #[tokio::test]
    async fn legacy_unlock_with_wrong_pin_passes_through_wrong_pin() {
        use bitwarden_core::client::encryption_settings::EncryptionSettingsError;
        use bitwarden_crypto::safe::{
            PasswordProtectedKeyEnvelope, PasswordProtectedKeyEnvelopeNamespace,
        };

        let (user_key, crypto_state) = make_test_user_crypto();
        let envelope = {
            let store: KeyStore<KeySlotIds> = KeyStore::default();
            let mut ctx = store.context_mut();
            let user_key_id = ctx.add_local_symmetric_key(user_key.clone());
            PasswordProtectedKeyEnvelope::seal(
                user_key_id,
                "1234",
                PasswordProtectedKeyEnvelopeNamespace::PinUnlock,
                &ctx,
            )
            .unwrap()
        };
        let mut request = init_request(&user_key, &crypto_state);
        request.method = InitUserCryptoMethod::PinEnvelope {
            pin: "0000".to_string(),
            pin_protected_user_key_envelope: envelope,
        };
        let client = Client::new_test(None);

        let result = client.unlock().unlock(UnlockMethod::Legacy(request)).await;

        assert!(
            matches!(
                result,
                Err(UnlockError::EncryptionSettings(
                    EncryptionSettingsError::WrongPin
                ))
            ),
            "A wrong PIN should pass through as WrongPin, got {result:?}"
        );
        assert_eq!(result.unwrap_err().to_string(), "Wrong Pin");
        assert!(
            !client
                .internal
                .get_key_store()
                .context()
                .has_symmetric_key(SymmetricKeySlotId::User),
            "A failed unlock should leave the client locked"
        );
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn unlock_on_unlocked_client_keeps_user_key_in_state_bridge() {
        use bitwarden_core::key_management::state_bridge::test_support::InMemoryStateBridge;

        let (user_key, crypto_state) = make_test_user_crypto();
        let client = Client::new_test(None);
        let bridge = client.km_state_bridge();
        bridge.register_bridge(Box::new(InMemoryStateBridge::default()));
        client
            .unlock()
            .unlock(UnlockMethod::Legacy(init_request(&user_key, &crypto_state)))
            .await
            .unwrap();

        let (other_user_key, other_crypto_state) = make_test_user_crypto();
        let result = client
            .unlock()
            .unlock(UnlockMethod::Legacy(init_request(
                &other_user_key,
                &other_crypto_state,
            )))
            .await;

        assert!(matches!(result, Err(UnlockError::AlreadyUnlocked)));
        assert_eq!(
            bridge
                .get_user_key()
                .await
                .map(|k| k.to_base64().to_string()),
            Some(user_key.to_base64().to_string()),
            "An AlreadyUnlocked result should leave the state bridge user key in place"
        );
        assert_eq!(user_key_base64(&client), user_key.to_base64().to_string());
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

    fn test_email() -> String {
        "test@bitwarden.com".to_string()
    }

    fn test_base_urls() -> BaseUrls {
        BaseUrls {
            identity_url: "https://identity.example.com".to_string(),
            api_url: "https://api.example.com".to_string(),
        }
    }

    fn has_user_key(client: &Client) -> bool {
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
        let user_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
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
                signed_public_key,
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
        let session_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
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
                email: test_email(),
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
                email: test_email(),
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
            !has_user_key(&client),
            "Rehydrated client should start locked"
        );

        client
            .unlock()
            .unlock(UnlockMethod::SessionKey(session_key))
            .await
            .unwrap();

        assert!(has_user_key(&client));
        assert_eq!(
            user_key_base64(&client),
            expected_user_key,
            "Unlocked user key should match the original"
        );
    }

    #[tokio::test]
    async fn unlock_with_session_key_on_unlocked_client_returns_already_unlocked() {
        ensure_platform_info();
        let (user_key, crypto_state) = make_test_user_crypto();
        let expected_user_key = user_key.to_base64().to_string();
        let (envelope, session_key) = seal_with_new_session_key(&user_key);

        let reg = populate_registry_for_unlock(envelope, crypto_state).await;
        let token_handler: Arc<dyn TokenHandler> = Arc::new(NoopTokenHandler);
        let client = Client::load_from_state(token_handler, reg).await.unwrap();
        client
            .unlock()
            .unlock(UnlockMethod::SessionKey(session_key.clone()))
            .await
            .unwrap();

        let result = client
            .unlock()
            .unlock(UnlockMethod::SessionKey(session_key))
            .await;

        assert!(matches!(result, Err(UnlockError::AlreadyUnlocked)));
        assert_eq!(user_key_base64(&client), expected_user_key);
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
                email: test_email(),
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

        let wrong_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::XAes256Gcm);
        let result = client
            .unlock()
            .unlock(UnlockMethod::SessionKey(SessionKey(wrong_key)))
            .await;
        assert!(matches!(result, Err(UnlockError::Unknown)));
    }
}
