#[cfg(feature = "internal")]
use bitwarden_crypto::{
    CryptoError, DeviceKey, EncString, Kdf, TrustDeviceResponse, UnsignedSharedKey,
};

#[cfg(feature = "secrets")]
use crate::auth::login::{login_access_token, AccessTokenLoginRequest, AccessTokenLoginResponse};
#[cfg(feature = "internal")]
use crate::{
    auth::{
        auth_request::{approve_auth_request, new_auth_request, ApproveAuthRequestError},
        key_connector::{make_key_connector_keys, KeyConnectorResponse},
        login::{
            login_api_key, login_password, send_two_factor_email, ApiKeyLoginRequest,
            ApiKeyLoginResponse, NewAuthRequestResponse, PasswordLoginRequest,
            PasswordLoginResponse, PreloginError, TwoFactorEmailError, TwoFactorEmailRequest,
        },
        password::{
            password_strength, satisfies_policy, validate_password, validate_password_user_key,
            MasterPasswordPolicyOptions,
        },
        pin::validate_pin,
        register::{make_register_keys, register},
        tde::{make_register_tde_keys, RegisterTdeKeyResponse},
        AuthRequestResponse, AuthValidateError, RegisterError, RegisterKeyResponse,
        RegisterRequest,
    },
    client::encryption_settings::EncryptionSettingsError,
};
use crate::{
    auth::{login::LoginError, renew::renew_token},
    Client,
};

pub struct AuthClient {
    pub(crate) client: crate::Client,
}

impl AuthClient {
    pub async fn renew_token(&self) -> Result<(), LoginError> {
        renew_token(&self.client.internal).await
    }

    #[cfg(feature = "secrets")]
    pub async fn login_access_token(
        &self,
        input: &AccessTokenLoginRequest,
    ) -> Result<AccessTokenLoginResponse, LoginError> {
        login_access_token(&self.client, input).await
    }
}

#[cfg(feature = "internal")]
impl AuthClient {
    pub fn password_strength(
        &self,
        password: String,
        email: String,
        additional_inputs: Vec<String>,
    ) -> u8 {
        password_strength(password, email, additional_inputs)
    }

    pub fn satisfies_policy(
        &self,
        password: String,
        strength: u8,
        policy: &MasterPasswordPolicyOptions,
    ) -> bool {
        satisfies_policy(password, strength, policy)
    }

    pub fn make_register_keys(
        &self,
        email: String,
        password: String,
        kdf: Kdf,
    ) -> Result<RegisterKeyResponse, CryptoError> {
        make_register_keys(email, password, kdf)
    }

    pub fn make_register_tde_keys(
        &self,
        email: String,
        org_public_key: String,
        remember_device: bool,
    ) -> Result<RegisterTdeKeyResponse, EncryptionSettingsError> {
        make_register_tde_keys(&self.client, email, org_public_key, remember_device)
    }

    pub fn make_key_connector_keys(&self) -> Result<KeyConnectorResponse, CryptoError> {
        let mut rng = rand::thread_rng();
        make_key_connector_keys(&mut rng)
    }

    pub async fn register(&self, input: &RegisterRequest) -> Result<(), RegisterError> {
        register(&self.client, input).await
    }

    pub async fn prelogin(&self, email: String) -> Result<Kdf, PreloginError> {
        use crate::auth::login::prelogin;

        prelogin(&self.client, email).await
    }

    pub async fn login_password(
        &self,
        input: &PasswordLoginRequest,
    ) -> Result<PasswordLoginResponse, LoginError> {
        login_password(&self.client, input).await
    }

    pub async fn login_api_key(
        &self,
        input: &ApiKeyLoginRequest,
    ) -> Result<ApiKeyLoginResponse, LoginError> {
        login_api_key(&self.client, input).await
    }

    pub async fn send_two_factor_email(
        &self,
        tf: &TwoFactorEmailRequest,
    ) -> Result<(), TwoFactorEmailError> {
        send_two_factor_email(&self.client, tf).await
    }

    pub fn validate_password(
        &self,
        password: String,
        password_hash: String,
    ) -> Result<bool, AuthValidateError> {
        validate_password(&self.client, password, password_hash)
    }

    pub fn validate_password_user_key(
        &self,
        password: String,
        encrypted_user_key: String,
    ) -> Result<String, AuthValidateError> {
        validate_password_user_key(&self.client, password, encrypted_user_key)
    }

    pub fn validate_pin(
        &self,
        pin: String,
        pin_protected_user_key: EncString,
    ) -> Result<bool, AuthValidateError> {
        validate_pin(&self.client, pin, pin_protected_user_key)
    }

    pub fn new_auth_request(&self, email: &str) -> Result<AuthRequestResponse, CryptoError> {
        new_auth_request(email)
    }

    pub fn approve_auth_request(
        &self,
        public_key: String,
    ) -> Result<UnsignedSharedKey, ApproveAuthRequestError> {
        approve_auth_request(&self.client, public_key)
    }

    pub fn trust_device(&self) -> Result<TrustDeviceResponse, TrustDeviceError> {
        trust_device(&self.client)
    }
}

#[cfg(feature = "internal")]
impl AuthClient {
    pub async fn login_device(
        &self,
        email: String,
        device_identifier: String,
    ) -> Result<NewAuthRequestResponse, LoginError> {
        use crate::auth::login::send_new_auth_request;

        send_new_auth_request(&self.client, email, device_identifier).await
    }

    pub async fn login_device_complete(
        &self,
        auth_req: NewAuthRequestResponse,
    ) -> Result<(), LoginError> {
        use crate::auth::login::complete_auth_request;

        complete_auth_request(&self.client, auth_req).await
    }
}

#[cfg(feature = "internal")]
#[derive(Debug, thiserror::Error)]
pub enum TrustDeviceError {
    #[error(transparent)]
    VaultLocked(#[from] crate::VaultLockedError),
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

#[cfg(feature = "internal")]
fn trust_device(client: &Client) -> Result<TrustDeviceResponse, TrustDeviceError> {
    use crate::key_management::SymmetricKeyId;

    let key_store = client.internal.get_key_store();
    let ctx = key_store.context();
    // FIXME: [PM-18099] Once DeviceKey deals with KeyIds, this should be updated
    #[allow(deprecated)]
    let user_key = ctx.dangerous_get_symmetric_key(SymmetricKeyId::User)?;

    Ok(DeviceKey::trust_device(user_key)?)
}

impl Client {
    pub fn auth(&self) -> AuthClient {
        AuthClient {
            client: self.clone(),
        }
    }
}
