#[cfg(feature = "internal")]
use bitwarden_crypto::Kdf;
#[cfg(feature = "internal")]
use log::info;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::auth::{
    api::response::IdentityTokenResponse, login::response::two_factor::TwoFactorProviders,
};
#[cfg(feature = "internal")]
use crate::{
    Client,
    auth::{api::request::PasswordTokenRequest, login::LoginError, login::TwoFactorRequest},
    client::LoginMethod,
};

#[cfg(feature = "internal")]
pub(crate) async fn login_password(
    client: &Client,
    input: &PasswordLoginRequest,
) -> Result<PasswordLoginResponse, LoginError> {
    use bitwarden_crypto::{EncString, HashPurpose, MasterKey};

    use crate::{
        client::{UserLoginMethod, internal::UserKeyState},
        require,
    };

    info!("password logging in");

    let master_key = MasterKey::derive(&input.password, &input.email, &input.kdf)?;
    let password_hash = master_key
        .derive_master_key_hash(input.password.as_bytes(), HashPurpose::ServerAuthorization);

    let response = request_identity_tokens(client, input, &password_hash.to_string()).await?;

    if let IdentityTokenResponse::Authenticated(r) = &response {
        client.internal.set_tokens(
            r.access_token.clone(),
            r.refresh_token.clone(),
            r.expires_in,
        );
        client
            .internal
            .set_login_method(LoginMethod::User(UserLoginMethod::Username {
                client_id: "web".to_owned(),
                email: input.email.to_owned(),
                kdf: input.kdf.to_owned(),
            }));

        let user_key: EncString = require!(r.key.as_deref()).parse()?;
        let private_key: EncString = require!(r.private_key.as_deref()).parse()?;

        client.internal.initialize_user_crypto_master_key(
            master_key,
            user_key,
            UserKeyState {
                private_key,
                signing_key: None,
                security_state: None,
            },
        )?;
    }

    Ok(PasswordLoginResponse::process_response(response))
}

#[cfg(feature = "internal")]
async fn request_identity_tokens(
    client: &Client,
    input: &PasswordLoginRequest,
    password_hash: &str,
) -> Result<IdentityTokenResponse, LoginError> {
    use crate::DeviceType;

    let config = client.internal.get_api_configurations().await;
    PasswordTokenRequest::new(
        &input.email,
        password_hash,
        DeviceType::ChromeBrowser,
        "b86dd6ab-4265-4ddf-a7f1-eb28d5677f33",
        &input.two_factor,
    )
    .send(&config)
    .await
}

/// Login to Bitwarden with Username and Password
#[cfg(feature = "internal")]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordLoginRequest {
    /// Bitwarden account email address
    pub email: String,
    /// Bitwarden account master password
    pub password: String,
    /// Two-factor authentication
    pub two_factor: Option<TwoFactorRequest>,
    /// Kdf from prelogin
    pub kdf: Kdf,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordLoginResponse {
    pub authenticated: bool,
    /// TODO: What does this do?
    pub reset_master_password: bool,
    /// Whether or not the user is required to update their master password
    pub force_password_reset: bool,
    /// The available two factor authentication options. Present only when authentication fails due
    /// to requiring a second authentication factor.
    pub two_factor: Option<TwoFactorProviders>,
}

impl PasswordLoginResponse {
    pub(crate) fn process_response(response: IdentityTokenResponse) -> PasswordLoginResponse {
        match response {
            IdentityTokenResponse::Authenticated(success) => PasswordLoginResponse {
                authenticated: true,
                reset_master_password: success.reset_master_password,
                force_password_reset: success.force_password_reset,
                two_factor: None,
            },
            IdentityTokenResponse::Payload(_) => PasswordLoginResponse {
                authenticated: true,
                reset_master_password: false,
                force_password_reset: false,
                two_factor: None,
            },
            IdentityTokenResponse::TwoFactorRequired(two_factor) => PasswordLoginResponse {
                authenticated: false,
                reset_master_password: false,
                force_password_reset: false,
                two_factor: Some(two_factor.two_factor_providers.into()),
            },
            IdentityTokenResponse::Refreshed(_) => {
                unreachable!("Got a `refresh_token` answer to a login request")
            }
        }
    }
}
