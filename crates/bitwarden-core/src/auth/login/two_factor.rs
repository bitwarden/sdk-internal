use bitwarden_api_api::models::TwoFactorEmailRequestModel;
use bitwarden_crypto::HashPurpose;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use thiserror::Error;

use crate::{
    ApiError, Client,
    auth::{login::PreloginError, password::determine_password_hash},
};

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TwoFactorEmailRequest {
    /// User Password
    pub password: String,
    /// User email
    pub email: String,
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum TwoFactorEmailError {
    #[error(transparent)]
    Prelogin(#[from] PreloginError),
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

pub(crate) async fn send_two_factor_email(
    client: &Client,
    input: &TwoFactorEmailRequest,
) -> Result<(), TwoFactorEmailError> {
    // TODO: This should be resolved from the client
    let kdf = client.auth().prelogin(input.email.clone()).await?;

    let password_hash = determine_password_hash(
        &input.email,
        &kdf,
        &input.password,
        HashPurpose::ServerAuthorization,
    )?;

    let config = client.internal.get_api_configurations().await;
    config
        .api_client
        .two_factor_api()
        .send_email_login(Some(TwoFactorEmailRequestModel {
            master_password_hash: Some(password_hash.to_string()),
            otp: None,
            auth_request_access_code: None,
            secret: None,
            email: input.email.to_owned(),
            auth_request_id: None,
            sso_email2_fa_session_token: None,
        }))
        .await
        .map_err(ApiError::from)?;

    Ok(())
}

#[allow(missing_docs)]
#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, JsonSchema, Clone)]
#[repr(u8)]
pub enum TwoFactorProvider {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    Yubikey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    WebAuthn = 7,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TwoFactorRequest {
    /// Two-factor Token
    pub token: String,
    /// Two-factor provider
    pub provider: TwoFactorProvider,
    /// Two-factor remember
    pub remember: bool,
}
