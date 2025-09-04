use bitwarden_crypto::{EncString, MasterKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    auth::{
        api::{request::ApiTokenRequest, response::IdentityTokenResponse},
        login::{response::two_factor::TwoFactorProviders, LoginError, PasswordLoginResponse},
        JwtToken,
    },
    client::{internal::UserKeyState, LoginMethod, UserLoginMethod},
    key_management::UserDecryptionData,
    require, Client,
};

pub(crate) async fn login_api_key(
    client: &Client,
    input: &ApiKeyLoginRequest,
) -> Result<ApiKeyLoginResponse, LoginError> {
    //info!("api key logging in");
    //debug!("{:#?}, {:#?}", client, input);

    let response = request_api_identity_tokens(client, input).await?;

    if let IdentityTokenResponse::Authenticated(r) = &response {
        let access_token_obj: JwtToken = r.access_token.parse()?;

        // This should always be Some() when logging in with an api key
        let email = access_token_obj
            .email
            .ok_or(LoginError::JwtTokenMissingEmail)?;

        let kdf = client.auth().prelogin(email.clone()).await?;

        client.internal.set_tokens(
            r.access_token.to_owned(),
            r.refresh_token.to_owned(),
            r.expires_in,
        );

        let private_key = r.private_key.as_deref();
        let private_key: EncString = require!(private_key).parse()?;

        let user_key_state = UserKeyState {
            private_key,
            signing_key: None,
            security_state: None,
        };

        if let Some(master_password_unlock) = r
            .user_decryption_options
            .as_ref()
            .map(UserDecryptionData::try_from)
            .transpose()?
            .and_then(|user_decryption| user_decryption.master_password_unlock)
        {
            client
                .internal
                .initialize_user_crypto_master_password_unlock(
                    input.password.clone(),
                    master_password_unlock,
                    user_key_state,
                )?;
        } else {
            let user_key = r.key.as_deref();
            let user_key: EncString = require!(user_key).parse()?;
            let master_key = MasterKey::derive(&input.password, &email, &kdf)?;

            client.internal.initialize_user_crypto_master_key(
                master_key,
                user_key,
                user_key_state,
            )?;
        }

        client
            .internal
            .set_login_method(LoginMethod::User(UserLoginMethod::ApiKey {
                client_id: input.client_id.clone(),
                client_secret: input.client_secret.clone(),
                email,
                kdf,
            }));
    }

    Ok(ApiKeyLoginResponse::process_response(response))
}

async fn request_api_identity_tokens(
    client: &Client,
    input: &ApiKeyLoginRequest,
) -> Result<IdentityTokenResponse, LoginError> {
    let config = client.internal.get_api_configurations().await;
    ApiTokenRequest::new(&input.client_id, &input.client_secret)
        .send(&config)
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
