#[cfg(feature = "internal")]
use bitwarden_crypto::{
    CryptoError, DeviceKey, EncString, Kdf, TrustDeviceResponse, UnsignedSharedKey,
};
#[cfg(feature = "internal")]
use bitwarden_encoding::B64;

#[cfg(feature = "secrets")]
use crate::auth::login::{AccessTokenLoginRequest, AccessTokenLoginResponse, login_access_token};
use crate::{
    Client,
    auth::{login::LoginError, renew::renew_token},
};
#[cfg(feature = "internal")]
use crate::{
    auth::{
        AuthRequestResponse, AuthValidateError, RegisterKeyResponse,
        auth_request::{ApproveAuthRequestError, approve_auth_request, new_auth_request},
        key_connector::{KeyConnectorResponse, make_key_connector_keys},
        login::{
            ApiKeyLoginRequest, ApiKeyLoginResponse, NewAuthRequestResponse, PasswordLoginRequest,
            PasswordLoginResponse, PreloginError, TwoFactorEmailError, TwoFactorEmailRequest,
            login_api_key, login_password, send_two_factor_email,
        },
        password::{
            MasterPasswordPolicyOptions, password_strength, satisfies_policy, validate_password,
            validate_password_user_key,
        },
        pin::validate_pin,
        register::make_register_keys,
        tde::{RegisterTdeKeyResponse, make_register_tde_keys},
    },
    client::encryption_settings::EncryptionSettingsError,
};

#[allow(missing_docs)]
pub struct AuthClient {
    pub(crate) client: crate::Client,
}

impl AuthClient {
    #[allow(missing_docs)]
    pub async fn renew_token(&self) -> Result<(), LoginError> {
        renew_token(&self.client.internal).await
    }

    #[allow(missing_docs)]
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
    #[allow(missing_docs)]
    pub fn password_strength(
        &self,
        password: String,
        email: String,
        additional_inputs: Vec<String>,
    ) -> u8 {
        password_strength(password, email, additional_inputs)
    }

    #[allow(missing_docs)]
    pub fn satisfies_policy(
        &self,
        password: String,
        strength: u8,
        policy: &MasterPasswordPolicyOptions,
    ) -> bool {
        satisfies_policy(password, strength, policy)
    }

    #[allow(missing_docs)]
    pub fn make_register_keys(
        &self,
        email: String,
        password: String,
        kdf: Kdf,
    ) -> Result<RegisterKeyResponse, CryptoError> {
        make_register_keys(email, password, kdf)
    }

    #[allow(missing_docs)]
    pub fn make_register_tde_keys(
        &self,
        email: String,
        org_public_key: B64,
        remember_device: bool,
    ) -> Result<RegisterTdeKeyResponse, EncryptionSettingsError> {
        make_register_tde_keys(&self.client, email, org_public_key, remember_device)
    }

    #[allow(missing_docs)]
    pub fn make_key_connector_keys(&self) -> Result<KeyConnectorResponse, CryptoError> {
        let mut rng = rand::thread_rng();
        make_key_connector_keys(&mut rng)
    }

    #[allow(missing_docs)]
    pub async fn prelogin(&self, email: String) -> Result<Kdf, PreloginError> {
        use crate::auth::login::prelogin;

        prelogin(&self.client, email).await
    }

    #[allow(missing_docs)]
    pub async fn login_password(
        &self,
        input: &PasswordLoginRequest,
    ) -> Result<PasswordLoginResponse, LoginError> {
        login_password(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn login_api_key(
        &self,
        input: &ApiKeyLoginRequest,
    ) -> Result<ApiKeyLoginResponse, LoginError> {
        login_api_key(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn send_two_factor_email(
        &self,
        tf: &TwoFactorEmailRequest,
    ) -> Result<(), TwoFactorEmailError> {
        send_two_factor_email(&self.client, tf).await
    }

    #[allow(missing_docs)]
    pub fn validate_password(
        &self,
        password: String,
        password_hash: B64,
    ) -> Result<bool, AuthValidateError> {
        validate_password(&self.client, password, password_hash)
    }

    #[allow(missing_docs)]
    pub fn validate_password_user_key(
        &self,
        password: String,
        encrypted_user_key: String,
    ) -> Result<B64, AuthValidateError> {
        validate_password_user_key(&self.client, password, encrypted_user_key)
    }

    #[allow(missing_docs)]
    pub fn validate_pin(
        &self,
        pin: String,
        pin_protected_user_key: EncString,
    ) -> Result<bool, AuthValidateError> {
        validate_pin(&self.client, pin, pin_protected_user_key)
    }

    #[allow(missing_docs)]
    pub fn new_auth_request(&self, email: &str) -> Result<AuthRequestResponse, CryptoError> {
        new_auth_request(email)
    }

    #[allow(missing_docs)]
    pub fn approve_auth_request(
        &self,
        public_key: B64,
    ) -> Result<UnsignedSharedKey, ApproveAuthRequestError> {
        approve_auth_request(&self.client, public_key)
    }

    #[allow(missing_docs)]
    pub fn trust_device(&self) -> Result<TrustDeviceResponse, TrustDeviceError> {
        trust_device(&self.client)
    }
}

#[cfg(feature = "internal")]
impl AuthClient {
    #[allow(missing_docs)]
    pub async fn login_device(
        &self,
        email: String,
        device_identifier: String,
    ) -> Result<NewAuthRequestResponse, LoginError> {
        use crate::auth::login::send_new_auth_request;

        send_new_auth_request(&self.client, email, device_identifier).await
    }

    #[allow(missing_docs)]
    pub async fn login_device_complete(
        &self,
        auth_req: NewAuthRequestResponse,
    ) -> Result<(), LoginError> {
        use crate::auth::login::complete_auth_request;

        complete_auth_request(&self.client, auth_req).await
    }
}

#[allow(missing_docs)]
#[cfg(feature = "internal")]
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum TrustDeviceError {
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
    #[allow(missing_docs)]
    pub fn auth(&self) -> AuthClient {
        AuthClient {
            client: self.clone(),
        }
    }
}
