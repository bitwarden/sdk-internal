use std::sync::{Arc, OnceLock, RwLock};

use bitwarden_crypto::KeyStore;
use bitwarden_server_communication_config::CookieProvider;
#[cfg(any(feature = "internal", feature = "secrets"))]
use bitwarden_crypto::SymmetricCryptoKey;
#[cfg(feature = "internal")]
use bitwarden_crypto::{
    EncString, Kdf, MasterKey, PinKey, UnsignedSharedKey, safe::PasswordProtectedKeyEnvelope,
};
#[cfg(feature = "internal")]
use bitwarden_state::registry::StateRegistry;
use chrono::Utc;
#[cfg(feature = "internal")]
use tracing::{info, instrument};

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
        encryption_settings::EncryptionSettingsError, flags::Flags, login_method::UserLoginMethod,
    },
    error::NotAuthenticatedError,
    key_management::{
        MasterPasswordUnlockData, SecurityState,
        account_cryptographic_state::WrappedAccountCryptographicState,
    },
};

#[allow(missing_docs)]
pub struct ApiConfigurations {
    pub identity_client: bitwarden_api_identity::apis::ApiClient,
    pub api_client: bitwarden_api_api::apis::ApiClient,
    pub identity_config: bitwarden_api_identity::Configuration,
    pub api_config: bitwarden_api_api::Configuration,
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
        identity_config: bitwarden_api_identity::Configuration,
        api_config: bitwarden_api_api::Configuration,
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

    pub(crate) fn get_key_connector_client(
        self: &Arc<Self>,
        key_connector_url: String,
    ) -> bitwarden_api_key_connector::apis::ApiClient {
        let api = self.api_config.clone();

        let key_connector = bitwarden_api_base::Configuration {
            base_path: key_connector_url,
            user_agent: api.user_agent,
            client: api.client,
            oauth_access_token: api.oauth_access_token,
        };

        bitwarden_api_key_connector::apis::ApiClient::new(&Arc::new(key_connector))
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
    pub(crate) external_http_client: reqwest::Client,

    pub(super) key_store: KeyStore<KeyIds>,
    #[cfg(feature = "internal")]
    pub(crate) security_state: RwLock<Option<SecurityState>>,

    #[cfg(feature = "internal")]
    pub(crate) repository_map: StateRegistry,

    /// Optional cookie provider for server communication middleware
    pub(crate) server_communication_config: Option<Arc<dyn CookieProvider>>,
}

impl std::fmt::Debug for InternalClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InternalClient")
            .field("user_id", &self.user_id)
            .field("tokens", &self.tokens)
            .field("login_method", &self.login_method)
            .field("__api_configurations", &self.__api_configurations)
            .field("key_store", &"<KeyStore>")
            .field("server_communication_config", &self.server_communication_config.as_ref().map(|_| "<CookieProvider>"))
            .finish_non_exhaustive()
    }
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
        use tracing::debug;

        debug!(?login_method, "setting login method.");
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

    pub fn get_key_connector_client(
        &self,
        key_connector_url: String,
    ) -> bitwarden_api_key_connector::apis::ApiClient {
        self.__api_configurations
            .read()
            .expect("RwLock is not poisoned")
            .get_key_connector_client(key_connector_url)
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
        &self.external_http_client
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
    #[instrument(err, skip_all)]
    pub(crate) fn initialize_user_crypto_key_connector_key(
        &self,
        master_key: MasterKey,
        user_key: EncString,
        account_crypto_state: WrappedAccountCryptographicState,
    ) -> Result<(), EncryptionSettingsError> {
        let user_key = master_key.decrypt_user_key(user_key)?;
        self.initialize_user_crypto_decrypted_key(user_key, account_crypto_state)
    }

    #[cfg(feature = "internal")]
    #[instrument(err, skip_all, fields(user_id = ?self.get_user_id()))]
    pub(crate) fn initialize_user_crypto_decrypted_key(
        &self,
        user_key: SymmetricCryptoKey,
        account_crypto_state: WrappedAccountCryptographicState,
    ) -> Result<(), EncryptionSettingsError> {
        let mut ctx = self.key_store.context_mut();

        // Note: The actual key does not get logged unless the crypto crate has the
        // dangerous-crypto-debug feature enabled, so this is safe
        info!("Setting user key {:?}", user_key);
        let user_key = ctx.add_local_symmetric_key(user_key);
        // The user key gets set to the local context frame here; It then gets persisted to the
        // context when the cryptographic state was unwrapped correctly, so that there is no
        // risk of a partial / incorrect setup.
        account_crypto_state
            .set_to_context(&self.security_state, user_key, &self.key_store, ctx)
            .map_err(|_| EncryptionSettingsError::CryptoInitialization)
    }

    #[cfg(feature = "internal")]
    #[instrument(err, skip_all)]
    pub(crate) fn initialize_user_crypto_pin(
        &self,
        pin_key: PinKey,
        pin_protected_user_key: EncString,
        account_crypto_state: WrappedAccountCryptographicState,
    ) -> Result<(), EncryptionSettingsError> {
        let decrypted_user_key = pin_key.decrypt_user_key(pin_protected_user_key)?;
        self.initialize_user_crypto_decrypted_key(decrypted_user_key, account_crypto_state)
    }

    #[cfg(feature = "internal")]
    #[instrument(err, skip_all)]
    pub(crate) fn initialize_user_crypto_pin_envelope(
        &self,
        pin: String,
        pin_protected_user_key_envelope: PasswordProtectedKeyEnvelope,
        account_crypto_state: WrappedAccountCryptographicState,
    ) -> Result<(), EncryptionSettingsError> {
        let decrypted_user_key = {
            // Note: This block ensures ctx is dropped. Otherwise it would cause a deadlock when
            // initializing the user crypto
            let ctx = &mut self.key_store.context_mut();
            let decrypted_user_key_id = pin_protected_user_key_envelope
                .unseal(&pin, ctx)
                .map_err(|_| EncryptionSettingsError::WrongPin)?;

            // Allowing deprecated here, until a refactor to pass the Local key ids to
            // `initialized_user_crypto_decrypted_key`
            #[allow(deprecated)]
            ctx.dangerous_get_symmetric_key(decrypted_user_key_id)?
                .clone()
        };
        self.initialize_user_crypto_decrypted_key(decrypted_user_key, account_crypto_state)
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

    #[cfg(feature = "internal")]
    #[instrument(err, skip_all)]
    pub(crate) fn initialize_user_crypto_master_password_unlock(
        &self,
        password: String,
        master_password_unlock: MasterPasswordUnlockData,
        account_crypto_state: WrappedAccountCryptographicState,
    ) -> Result<(), EncryptionSettingsError> {
        let master_key = MasterKey::derive(
            &password,
            &master_password_unlock.salt,
            &master_password_unlock.kdf,
        )?;
        let user_key =
            master_key.decrypt_user_key(master_password_unlock.master_key_wrapped_user_key)?;
        self.initialize_user_crypto_decrypted_key(user_key, account_crypto_state)
    }

    /// Sets the local KDF state for the master password unlock login method.
    /// Salt and user key update is not supported yet.
    #[cfg(feature = "internal")]
    pub fn set_user_master_password_unlock(
        &self,
        master_password_unlock: MasterPasswordUnlockData,
    ) -> Result<(), NotAuthenticatedError> {
        let new_kdf = master_password_unlock.kdf;

        let login_method = self.get_login_method().ok_or(NotAuthenticatedError)?;

        let kdf = self.get_kdf()?;

        if kdf != new_kdf {
            match login_method.as_ref() {
                LoginMethod::User(UserLoginMethod::Username {
                    client_id, email, ..
                }) => self.set_login_method(LoginMethod::User(UserLoginMethod::Username {
                    client_id: client_id.to_owned(),
                    email: email.to_owned(),
                    kdf: new_kdf,
                })),
                LoginMethod::User(UserLoginMethod::ApiKey {
                    client_id,
                    client_secret,
                    email,
                    ..
                }) => self.set_login_method(LoginMethod::User(UserLoginMethod::ApiKey {
                    client_id: client_id.to_owned(),
                    client_secret: client_secret.to_owned(),
                    email: email.to_owned(),
                    kdf: new_kdf,
                })),
                #[cfg(feature = "secrets")]
                LoginMethod::ServiceAccount(_) => return Err(NotAuthenticatedError),
            };
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use bitwarden_crypto::{EncString, Kdf, MasterKey};

    use crate::{
        Client,
        client::{LoginMethod, UserLoginMethod, test_accounts::test_bitwarden_com_account},
        key_management::MasterPasswordUnlockData,
    };

    const TEST_ACCOUNT_EMAIL: &str = "test@bitwarden.com";
    const TEST_ACCOUNT_USER_KEY: &str = "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=";

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

    #[tokio::test]
    async fn test_set_user_master_password_unlock_kdf_updated() {
        let new_kdf = Kdf::Argon2id {
            iterations: NonZeroU32::new(4).unwrap(),
            memory: NonZeroU32::new(65).unwrap(),
            parallelism: NonZeroU32::new(5).unwrap(),
        };

        let user_key: EncString = TEST_ACCOUNT_USER_KEY.parse().expect("Invalid user key");
        let email = TEST_ACCOUNT_EMAIL.to_owned();

        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        client
            .internal
            .set_user_master_password_unlock(MasterPasswordUnlockData {
                kdf: new_kdf.clone(),
                master_key_wrapped_user_key: user_key,
                salt: email,
            })
            .unwrap();

        let kdf = client.internal.get_kdf().unwrap();
        assert_eq!(kdf, new_kdf);
    }

    #[tokio::test]
    async fn test_set_user_master_password_unlock_email_and_keys_not_updated() {
        let password = "asdfasdfasdf".to_string();
        let new_email = format!("{}@example.com", uuid::Uuid::new_v4());
        let kdf = Kdf::default_pbkdf2();
        let expected_email = TEST_ACCOUNT_EMAIL.to_owned();

        let (new_user_key, new_encrypted_user_key) = {
            let master_key = MasterKey::derive(&password, &new_email, &kdf).unwrap();
            master_key.make_user_key().unwrap()
        };

        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        client
            .internal
            .set_user_master_password_unlock(MasterPasswordUnlockData {
                kdf,
                master_key_wrapped_user_key: new_encrypted_user_key,
                salt: new_email,
            })
            .unwrap();

        let login_method = client.internal.get_login_method().unwrap();
        match login_method.as_ref() {
            LoginMethod::User(UserLoginMethod::Username { email, .. }) => {
                assert_eq!(*email, expected_email);
            }
            _ => panic!("Expected username login method"),
        }

        let user_key = client.crypto().get_user_encryption_key().await.unwrap();

        assert_ne!(user_key, new_user_key.0.to_base64());
    }
}
