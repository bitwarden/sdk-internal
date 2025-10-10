use std::sync::{Arc, OnceLock, RwLock};

use bitwarden_crypto::KeyStore;
#[cfg(any(feature = "internal", feature = "secrets"))]
use bitwarden_crypto::SymmetricCryptoKey;
#[cfg(feature = "internal")]
use bitwarden_crypto::{CryptoError, EncString, Kdf, MasterKey, PinKey, UnsignedSharedKey};
#[cfg(feature = "internal")]
use bitwarden_state::registry::StateRegistry;
use chrono::Utc;

#[cfg(any(feature = "internal", feature = "secrets"))]
use crate::client::encryption_settings::EncryptionSettings;
#[cfg(feature = "secrets")]
use crate::client::login_method::ServiceAccountLoginMethod;
use crate::{
    DeviceType, OrganizationId, UserId, auth::renew::renew_token,
    client::login_method::LoginMethod, error::UserIdAlreadySetError, key_management::KeyIds,
};
#[cfg(feature = "internal")]
use crate::{
    client::{
        encryption_settings::{AccountEncryptionKeys, EncryptionSettingsError},
        flags::Flags,
        login_method::UserLoginMethod,
    },
    error::NotAuthenticatedError,
    key_management::{
        PasswordProtectedKeyEnvelope, SecurityState, SignedSecurityState,
        crypto::InitUserCryptoRequest,
    },
};

/// Represents the user's keys, that are encrypted by the user key, and the signed security state.
#[cfg(feature = "internal")]
pub(crate) struct UserKeyState {
    pub(crate) private_key: EncString,
    pub(crate) signing_key: Option<EncString>,
    pub(crate) security_state: Option<SignedSecurityState>,
}
#[cfg(feature = "internal")]
impl From<&InitUserCryptoRequest> for UserKeyState {
    fn from(req: &InitUserCryptoRequest) -> Self {
        UserKeyState {
            private_key: req.private_key.clone(),
            signing_key: req.signing_key.clone(),
            security_state: req.security_state.clone(),
        }
    }
}

#[allow(missing_docs)]
pub struct ApiConfigurations {
    pub identity_client: bitwarden_api_identity::apis::ApiClient,
    pub api_client: bitwarden_api_api::apis::ApiClient,
    pub identity_config: bitwarden_api_identity::apis::configuration::Configuration,
    pub api_config: bitwarden_api_api::apis::configuration::Configuration,
    pub device_type: DeviceType,
}

impl std::fmt::Debug for ApiConfigurations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiConfigurations")
            .field("device_type", &self.device_type)
            .finish_non_exhaustive()
    }
}

impl ApiConfigurations {
    pub(crate) fn new(
        identity_config: bitwarden_api_identity::apis::configuration::Configuration,
        api_config: bitwarden_api_api::apis::configuration::Configuration,
        device_type: DeviceType,
    ) -> Arc<Self> {
        let identity = Arc::new(identity_config.clone());
        let api = Arc::new(api_config.clone());
        let identity_client = bitwarden_api_identity::apis::ApiClient::new(&identity);
        let api_client = bitwarden_api_api::apis::ApiClient::new(&api);
        Arc::new(Self {
            identity_client,
            api_client,
            identity_config,
            api_config,
            device_type,
        })
    }

    pub fn set_tokens(self: &mut Arc<Self>, token: String) {
        let mut identity = self.identity_config.clone();
        let mut api = self.api_config.clone();

        identity.oauth_access_token = Some(token.clone());
        api.oauth_access_token = Some(token);

        *self = ApiConfigurations::new(identity, api, self.device_type);
    }
}

/// Access and refresh tokens used for authentication and authorization.
#[derive(Debug, Clone)]
pub(crate) enum Tokens {
    SdkManaged(SdkManagedTokens),
    ClientManaged(Arc<dyn ClientManagedTokens>),
}

/// Access tokens managed by client applications, such as the web or mobile apps.
#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
#[async_trait::async_trait]
pub trait ClientManagedTokens: std::fmt::Debug + Send + Sync {
    /// Returns the access token, if available.
    async fn get_access_token(&self) -> Option<String>;
}

/// Tokens managed by the SDK, the SDK will automatically handle token renewal.
#[derive(Debug, Default, Clone)]
pub(crate) struct SdkManagedTokens {
    // These two fields are always written to, but they are not read
    // from the secrets manager SDK.
    #[allow(dead_code)]
    access_token: Option<String>,
    pub(crate) expires_on: Option<i64>,

    #[cfg_attr(not(feature = "internal"), allow(dead_code))]
    pub(crate) refresh_token: Option<String>,
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct InternalClient {
    pub(crate) user_id: OnceLock<UserId>,
    pub(crate) tokens: RwLock<Tokens>,
    pub(crate) login_method: RwLock<Option<Arc<LoginMethod>>>,

    #[cfg(feature = "internal")]
    pub(super) flags: RwLock<Flags>,

    /// Use Client::get_api_configurations().await to access this.
    /// It should only be used directly in renew_token
    #[doc(hidden)]
    pub(crate) __api_configurations: RwLock<Arc<ApiConfigurations>>,

    /// Reqwest client useable for external integrations like email forwarders, HIBP.
    #[allow(unused)]
    pub(crate) external_client: reqwest::Client,

    pub(super) key_store: KeyStore<KeyIds>,
    #[cfg(feature = "internal")]
    pub(crate) security_state: RwLock<Option<SecurityState>>,

    #[cfg(feature = "internal")]
    pub(crate) repository_map: StateRegistry,
}

impl InternalClient {
    /// Load feature flags. This is intentionally a collection and not the internal `Flag` enum as
    /// we want to avoid changes in feature flags from being a breaking change.
    #[cfg(feature = "internal")]
    pub fn load_flags(&self, flags: std::collections::HashMap<String, bool>) {
        *self.flags.write().expect("RwLock is not poisoned") = Flags::load_from_map(flags);
    }

    /// Retrieve the active feature flags.
    #[cfg(feature = "internal")]
    pub fn get_flags(&self) -> Flags {
        self.flags.read().expect("RwLock is not poisoned").clone()
    }

    #[cfg(feature = "internal")]
    pub(crate) fn get_login_method(&self) -> Option<Arc<LoginMethod>> {
        self.login_method
            .read()
            .expect("RwLock is not poisoned")
            .clone()
    }

    #[allow(missing_docs)]
    pub fn get_access_token_organization(&self) -> Option<OrganizationId> {
        match self
            .login_method
            .read()
            .expect("RwLock is not poisoned")
            .as_deref()
        {
            #[cfg(feature = "secrets")]
            Some(LoginMethod::ServiceAccount(ServiceAccountLoginMethod::AccessToken {
                organization_id,
                ..
            })) => Some(*organization_id),
            _ => None,
        }
    }

    #[cfg(any(feature = "internal", feature = "secrets"))]
    pub(crate) fn set_login_method(&self, login_method: LoginMethod) {
        use log::debug;

        debug! {"setting login method: {login_method:#?}"}
        *self.login_method.write().expect("RwLock is not poisoned") = Some(Arc::new(login_method));
    }

    pub(crate) fn set_tokens(&self, token: String, refresh_token: Option<String>, expires_in: u64) {
        *self.tokens.write().expect("RwLock is not poisoned") =
            Tokens::SdkManaged(SdkManagedTokens {
                access_token: Some(token.clone()),
                expires_on: Some(Utc::now().timestamp() + expires_in as i64),
                refresh_token,
            });
        self.set_api_tokens_internal(token);
    }

    /// Sets api tokens for only internal API clients, use `set_tokens` for SdkManagedTokens.
    pub(crate) fn set_api_tokens_internal(&self, token: String) {
        self.__api_configurations
            .write()
            .expect("RwLock is not poisoned")
            .set_tokens(token);
    }

    #[allow(missing_docs)]
    #[cfg(feature = "internal")]
    pub fn get_kdf(&self) -> Result<Kdf, NotAuthenticatedError> {
        match self
            .login_method
            .read()
            .expect("RwLock is not poisoned")
            .as_deref()
        {
            Some(LoginMethod::User(
                UserLoginMethod::Username { kdf, .. } | UserLoginMethod::ApiKey { kdf, .. },
            )) => Ok(kdf.clone()),
            _ => Err(NotAuthenticatedError),
        }
    }

    #[allow(missing_docs)]
    pub async fn get_api_configurations(&self) -> Arc<ApiConfigurations> {
        // At the moment we ignore the error result from the token renewal, if it fails,
        // the token will end up expiring and the next operation is going to fail anyway.
        renew_token(self).await.ok();
        self.__api_configurations
            .read()
            .expect("RwLock is not poisoned")
            .clone()
    }

    #[allow(missing_docs)]
    #[cfg(feature = "internal")]
    pub fn get_http_client(&self) -> &reqwest::Client {
        &self.external_client
    }

    #[allow(missing_docs)]
    pub fn get_key_store(&self) -> &KeyStore<KeyIds> {
        &self.key_store
    }

    /// Returns the security version of the user.
    /// `1` is returned for V1 users that do not have a signed security state.
    /// `2` or greater is returned for V2 users that have a signed security state.
    #[cfg(feature = "internal")]
    pub fn get_security_version(&self) -> u64 {
        self.security_state
            .read()
            .expect("RwLock is not poisoned")
            .as_ref()
            .map_or(1, |state| state.version())
    }

    #[allow(missing_docs)]
    pub fn init_user_id(&self, user_id: UserId) -> Result<(), UserIdAlreadySetError> {
        let set_uuid = self.user_id.get_or_init(|| user_id);

        // Only return an error if the user_id is already set to a different value,
        // as we want an SDK client to be tied to a single user_id.
        // If it's the same value, we can just do nothing.
        if *set_uuid != user_id {
            Err(UserIdAlreadySetError)
        } else {
            Ok(())
        }
    }

    #[allow(missing_docs)]
    pub fn get_user_id(&self) -> Option<UserId> {
        self.user_id.get().copied()
    }

    #[cfg(feature = "internal")]
    pub(crate) fn initialize_user_crypto_master_key(
        &self,
        master_key: MasterKey,
        user_key: EncString,
        key_state: UserKeyState,
    ) -> Result<(), EncryptionSettingsError> {
        let user_key = master_key.decrypt_user_key(user_key)?;
        self.initialize_user_crypto_decrypted_key(user_key, key_state)
    }

    #[cfg(feature = "internal")]
    pub(crate) fn initialize_user_crypto_decrypted_key(
        &self,
        user_key: SymmetricCryptoKey,
        key_state: UserKeyState,
    ) -> Result<(), EncryptionSettingsError> {
        match user_key {
            SymmetricCryptoKey::Aes256CbcHmacKey(ref user_key) => {
                EncryptionSettings::new_decrypted_key(
                    AccountEncryptionKeys::V1 {
                        user_key: user_key.clone(),
                        private_key: key_state.private_key,
                    },
                    &self.key_store,
                    &self.security_state,
                )?;
            }
            SymmetricCryptoKey::XChaCha20Poly1305Key(ref user_key) => {
                EncryptionSettings::new_decrypted_key(
                    AccountEncryptionKeys::V2 {
                        user_key: user_key.clone(),
                        private_key: key_state.private_key,
                        signing_key: key_state
                            .signing_key
                            .ok_or(EncryptionSettingsError::InvalidSigningKey)?,
                        security_state: key_state
                            .security_state
                            .ok_or(EncryptionSettingsError::InvalidSecurityState)?,
                    },
                    &self.key_store,
                    &self.security_state,
                )?;
            }
            _ => {
                return Err(CryptoError::InvalidKey.into());
            }
        }

        Ok(())
    }

    #[cfg(feature = "internal")]
    pub(crate) fn initialize_user_crypto_pin(
        &self,
        pin_key: PinKey,
        pin_protected_user_key: EncString,
        key_state: UserKeyState,
    ) -> Result<(), EncryptionSettingsError> {
        let decrypted_user_key = pin_key.decrypt_user_key(pin_protected_user_key)?;
        self.initialize_user_crypto_decrypted_key(decrypted_user_key, key_state)
    }

    #[cfg(feature = "internal")]
    pub(crate) fn initialize_user_crypto_pin_envelope(
        &self,
        pin: String,
        pin_protected_user_key_envelope: PasswordProtectedKeyEnvelope,
        key_state: UserKeyState,
    ) -> Result<(), EncryptionSettingsError> {
        let decrypted_user_key = {
            // Note: This block ensures ctx is dropped. Otherwise it would cause a deadlock when
            // initializing the user crypto
            use crate::key_management::SymmetricKeyId;
            let ctx = &mut self.key_store.context_mut();
            let decrypted_user_key_id = pin_protected_user_key_envelope
                .unseal(SymmetricKeyId::Local("tmp_unlock_pin"), &pin, ctx)
                .map_err(|_| EncryptionSettingsError::WrongPin)?;

            // Allowing deprecated here, until a refactor to pass the Local key ids to
            // `initialized_user_crypto_decrypted_key`
            #[allow(deprecated)]
            ctx.dangerous_get_symmetric_key(decrypted_user_key_id)?
                .clone()
        };
        self.initialize_user_crypto_decrypted_key(decrypted_user_key, key_state)
    }

    #[cfg(feature = "secrets")]
    pub(crate) fn initialize_crypto_single_org_key(
        &self,
        organization_id: OrganizationId,
        key: SymmetricCryptoKey,
    ) {
        EncryptionSettings::new_single_org_key(organization_id, key, &self.key_store);
    }

    #[allow(missing_docs)]
    #[cfg(feature = "internal")]
    pub fn initialize_org_crypto(
        &self,
        org_keys: Vec<(OrganizationId, UnsignedSharedKey)>,
    ) -> Result<(), EncryptionSettingsError> {
        EncryptionSettings::set_org_keys(org_keys, &self.key_store)
    }
}

#[cfg(test)]
mod tests {
    use crate::Client;

    #[test]
    fn initializing_user_multiple_times() {
        use super::*;

        let client = Client::new(None);
        let user_id = UserId::new_v4();

        // Setting the user ID for the first time should work.
        assert!(client.internal.init_user_id(user_id).is_ok());
        assert_eq!(client.internal.get_user_id(), Some(user_id));

        // Trying to set the same user_id again should not return an error.
        assert!(client.internal.init_user_id(user_id).is_ok());

        // Trying to set a different user_id should return an error.
        let different_user_id = UserId::new_v4();
        assert!(client.internal.init_user_id(different_user_id).is_err());
    }
}
