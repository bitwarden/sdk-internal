use bitwarden_crypto::EncString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    Client,
    auth::{
        api::{request::ApiTokenRequest, response::IdentityTokenResponse},
        login::{LoginError, PasswordLoginResponse, response::two_factor::TwoFactorProviders},
    },
    client::{LoginMethod, UserLoginMethod},
    key_management::{
        UserDecryptionData, account_cryptographic_state::WrappedAccountCryptographicState,
    },
    require,
};

pub(crate) async fn login_api_key(
    client: &Client,
    input: &ApiKeyLoginRequest,
) -> Result<ApiKeyLoginResponse, LoginError> {
    //info!("api key logging in");
    //debug!("{:#?}, {:#?}", client, input);

    let response = request_api_identity_tokens(client, input).await?;

    if let IdentityTokenResponse::Authenticated(r) = &response {
        client.internal.set_tokens(
            r.access_token.clone(),
            r.refresh_token.clone(),
            r.expires_in,
        );

        let private_key: EncString = require!(&r.private_key).parse()?;

        let user_key_state = WrappedAccountCryptographicState::V1 { private_key };

        let master_password_unlock = r
            .user_decryption_options
            .as_ref()
            .map(UserDecryptionData::try_from)
            .transpose()?
            .and_then(|user_decryption| user_decryption.master_password_unlock);
        if let Some(master_password_unlock) = master_password_unlock {
            client
                .internal
                .initialize_user_crypto_master_password_unlock(
                    input.password.clone(),
                    master_password_unlock.clone(),
                    user_key_state,
                )?;

            client
                .internal
                .set_login_method(LoginMethod::User(UserLoginMethod::ApiKey {
                    client_id: input.client_id.clone(),
                    client_secret: input.client_secret.clone(),
                    email: master_password_unlock.salt,
                    kdf: master_password_unlock.kdf,
                }));
        }
    }

    Ok(ApiKeyLoginResponse::process_response(response))
}

async fn request_api_identity_tokens(
    client: &Client,
    input: &ApiKeyLoginRequest,
) -> Result<IdentityTokenResponse, LoginError> {
    let config = client.internal.get_api_configurations();
    ApiTokenRequest::new(&input.client_id, &input.client_secret)
        .send(&config.identity_config)
        .await
}

/// Login to Bitwarden with Api Key
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApiKeyLoginRequest {
    /// Bitwarden account client_id
    pub client_id: String,
    /// Bitwarden account client_secret
    pub client_secret: String,

    /// Bitwarden account master password
    pub password: String,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApiKeyLoginResponse {
    pub authenticated: bool,
    /// TODO: What does this do?
    pub reset_master_password: bool,
    /// Whether or not the user is required to update their master password
    pub force_password_reset: bool,
    two_factor: Option<TwoFactorProviders>,
}

impl ApiKeyLoginResponse {
    pub(crate) fn process_response(response: IdentityTokenResponse) -> ApiKeyLoginResponse {
        let password_response = PasswordLoginResponse::process_response(response);

        ApiKeyLoginResponse {
            authenticated: password_response.authenticated,
            reset_master_password: password_response.reset_master_password,
            force_password_reset: password_response.force_password_reset,
            two_factor: password_response.two_factor,
        }
    }
}
