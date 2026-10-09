use std::path::{Path, PathBuf};

use bitwarden_access_token::{AccessTokenKind, ExportedKey};
use bitwarden_sensitive_value::ExposeSensitive as _;
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
    key_management::SymmetricKeySlotId,
    require,
    secrets_manager::state::{self, ClientState},
};

pub(crate) async fn login_access_token(
    client: &Client,
    input: &AccessTokenLoginRequest,
) -> Result<AccessTokenLoginResponse, LoginError> {
    //info!("api key logging in");
    //debug!("{:#?}, {:#?}", client, input);

    let access_token = AccessToken::parse(&input.access_token, AccessTokenKind::SecretsManager)?;

    if let Some(state_file) = &input.state_file
        && let Ok(organization_id) = load_tokens_from_state(client, state_file, &access_token).await
    {
        client
            .internal
            .set_login_method(LoginMethod::ServiceAccount(
                ServiceAccountLoginMethod::AccessToken {
                    access_token,
                    organization_id,
                    state_file: Some(state_file.to_path_buf()),
                },
            ))
            .await;

        return Ok(AccessTokenLoginResponse {
            authenticated: true,
            reset_master_password: false,
            force_password_reset: false,
            two_factor: None,
        });
    }

    let response = request_access_token(client, &access_token).await?;

    if let IdentityTokenResponse::Payload(r) = &response {
        let access_token_obj: JwtToken = r.access_token.parse()?;

        // This should always be Some() when logging in with an access token
        let organization_id: OrganizationId = require!(access_token_obj.organization)
            .parse()
            .map_err(|_| LoginError::InvalidResponse)?;
        let organization_key_id = SymmetricKeySlotId::Organization(organization_id);

        // The payload holds the organization key, encrypted under the access token's key
        let key_store = client.internal.get_key_store();
        access_token.open_payload(
            &mut key_store.context_mut(),
            &r.encrypted_payload,
            organization_key_id,
        )?;

        if let Some(state_file) = &input.state_file {
            let new_state = ClientState::new(
                r.access_token.clone(),
                ExportedKey::from_slot(&key_store.context(), organization_key_id)?,
            );
            _ = state::set(state_file, &access_token, &new_state);
        }

        client
            .internal
            .set_tokens(
                r.access_token.clone(),
                r.refresh_token.clone(),
                r.expires_in,
            )
            .await;

        client
            .internal
            .set_login_method(LoginMethod::ServiceAccount(
                ServiceAccountLoginMethod::AccessToken {
                    access_token,
                    organization_id,
                    state_file: input.state_file.clone(),
                },
            ))
            .await;
    }

    AccessTokenLoginResponse::process_response(response)
}

async fn request_access_token(
    client: &Client,
    input: &AccessToken,
) -> Result<IdentityTokenResponse, LoginError> {
    let config = client.internal.get_api_configurations();
    AccessTokenRequest::new(input.api_key_id(), input.client_secret().expose())
        .send(&config.identity_config)
        .await
}

async fn load_tokens_from_state(
    client: &Client,
    state_file: &Path,
    access_token: &AccessToken,
) -> Result<OrganizationId, LoginError> {
    let state = state::get(state_file, access_token)?;
    let token: JwtToken = state.token.parse()?;

    if let Some(organization_id) = token.organization {
        let time_till_expiration = (token.exp as i64) - Utc::now().timestamp();

        if time_till_expiration > 0 {
            let organization_id: OrganizationId = organization_id
                .parse()
                .map_err(|_| LoginError::InvalidOrganizationId)?;

            client
                .internal
                .set_tokens(state.token.clone(), None, time_till_expiration as u64)
                .await;

            let key_store = client.internal.get_key_store();
            state.encryption_key.install(
                &mut key_store.context_mut(),
                SymmetricKeySlotId::Organization(organization_id),
            )?;

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
