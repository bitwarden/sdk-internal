use std::path::{Path, PathBuf};

use bitwarden_crypto::{BitwardenLegacyKeyBytes, EncString, KeyDecryptable, SymmetricCryptoKey};
use bitwarden_encoding::B64;
use chrono::Utc;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::LoginError;
use crate::{
    Client, OrganizationId,
    auth::{
        AccessToken, JwtToken,
        api::{request::AccessTokenRequest, response::IdentityTokenResponse},
        login::{PasswordLoginResponse, response::two_factor::TwoFactorProviders},
    },
    client::{LoginMethod, ServiceAccountLoginMethod},
    require,
    secrets_manager::state::{self, ClientState},
};

pub(crate) async fn login_access_token(
    client: &Client,
    input: &AccessTokenLoginRequest,
) -> Result<AccessTokenLoginResponse, LoginError> {
    //info!("api key logging in");
    //debug!("{:#?}, {:#?}", client, input);

    let access_token: AccessToken = input.access_token.parse()?;

    if let Some(state_file) = &input.state_file {
        if let Ok(organization_id) = load_tokens_from_state(client, state_file, &access_token) {
            client
                .internal
                .set_login_method(LoginMethod::ServiceAccount(
                    ServiceAccountLoginMethod::AccessToken {
                        access_token,
                        organization_id,
                        state_file: Some(state_file.to_path_buf()),
                    },
                ));

            return Ok(AccessTokenLoginResponse {
                authenticated: true,
                reset_master_password: false,
                force_password_reset: false,
                two_factor: None,
            });
        }
    }

    let response = request_access_token(client, &access_token).await?;

    if let IdentityTokenResponse::Payload(r) = &response {
        // Extract the encrypted payload and use the access token encryption key to decrypt it
        let payload: EncString = r.encrypted_payload.parse()?;

        let decrypted_payload: Vec<u8> = payload.decrypt_with_key(&access_token.encryption_key)?;

        // Once decrypted, we have to JSON decode to extract the organization encryption key
        #[derive(serde::Deserialize)]
        struct Payload {
            #[serde(rename = "encryptionKey")]
            encryption_key: B64,
        }

        let payload: Payload = serde_json::from_slice(&decrypted_payload)?;
        let encryption_key = BitwardenLegacyKeyBytes::from(&payload.encryption_key);
        let encryption_key = SymmetricCryptoKey::try_from(&encryption_key)?;

        let access_token_obj: JwtToken = r.access_token.parse()?;

        // This should always be Some() when logging in with an access token
        let organization_id = require!(access_token_obj.organization)
            .parse()
            .map_err(|_| LoginError::InvalidResponse)?;

        if let Some(state_file) = &input.state_file {
            let state = ClientState::new(r.access_token.clone(), payload.encryption_key);
            _ = state::set(state_file, &access_token, state);
        }

        client.internal.set_tokens(
            r.access_token.clone(),
            r.refresh_token.clone(),
            r.expires_in,
        );
        client
            .internal
            .set_login_method(LoginMethod::ServiceAccount(
                ServiceAccountLoginMethod::AccessToken {
                    access_token,
                    organization_id,
                    state_file: input.state_file.clone(),
                },
            ));

        client
            .internal
            .initialize_crypto_single_org_key(organization_id, encryption_key);
    }

    AccessTokenLoginResponse::process_response(response)
}

async fn request_access_token(
    client: &Client,
    input: &AccessToken,
) -> Result<IdentityTokenResponse, LoginError> {
    let config = client.internal.get_api_configurations().await;
    AccessTokenRequest::new(input.access_token_id, &input.client_secret)
        .send(&config)
        .await
}

fn load_tokens_from_state(
    client: &Client,
    state_file: &Path,
    access_token: &AccessToken,
) -> Result<OrganizationId, LoginError> {
    let client_state = state::get(state_file, access_token)?;

    let token: JwtToken = client_state.token.parse()?;

    if let Some(organization_id) = token.organization {
        let time_till_expiration = (token.exp as i64) - Utc::now().timestamp();

        if time_till_expiration > 0 {
            let organization_id: OrganizationId = organization_id
                .parse()
                .map_err(|_| LoginError::InvalidOrganizationId)?;
            let encryption_key = SymmetricCryptoKey::try_from(client_state.encryption_key)?;

            client
                .internal
                .set_tokens(client_state.token, None, time_till_expiration as u64);
            client
                .internal
                .initialize_crypto_single_org_key(organization_id, encryption_key);

            return Ok(organization_id);
        }
    }

    Err(LoginError::InvalidStateFile)
}

/// Login to Bitwarden with access token
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessTokenLoginRequest {
    /// Bitwarden service API access token
    pub access_token: String,
    /// Path to the state file
    pub state_file: Option<PathBuf>,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessTokenLoginResponse {
    pub authenticated: bool,
    /// TODO: What does this do?
    pub reset_master_password: bool,
    /// Whether or not the user is required to update their master password
    pub force_password_reset: bool,
    two_factor: Option<TwoFactorProviders>,
}

impl AccessTokenLoginResponse {
    pub(crate) fn process_response(
        response: IdentityTokenResponse,
    ) -> Result<AccessTokenLoginResponse, LoginError> {
        let password_response = PasswordLoginResponse::process_response(response);

        Ok(AccessTokenLoginResponse {
            authenticated: password_response.authenticated,
            reset_master_password: password_response.reset_master_password,
            force_password_reset: password_response.force_password_reset,
            two_factor: password_response.two_factor,
        })
    }
}
