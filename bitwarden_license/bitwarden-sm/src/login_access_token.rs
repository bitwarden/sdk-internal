//! Secrets Manager access token login implementation.
//!
//! This module owns the access-token login flow for SM service accounts,
//! extracted from bitwarden-core as part of PM-25937.

use std::path::Path;

use bitwarden_auth::{
    AccessToken,
    login::access_token::{AccessTokenLoginRequest, AccessTokenLoginResponse},
    service_account_login_method::ServiceAccountLoginMethod,
    sm_request::{IdentityTokenResponse, send_access_token_request},
};
use bitwarden_core::{
    OrganizationId,
    auth::{JwtToken, TokenHandler, login::LoginError},
    key_management::SymmetricKeySlotId,
};
use bitwarden_crypto::{EncString, KeyDecryptable, SymmetricCryptoKey};
use bitwarden_encoding::B64;
use chrono::Utc;

use crate::{
    client::SecretsManagerClient,
    state::{self, ClientState},
};

/// Log in to Bitwarden Secrets Manager using a service account access token.
pub(crate) async fn login_access_token(
    client: &SecretsManagerClient,
    input: &AccessTokenLoginRequest,
) -> Result<AccessTokenLoginResponse, LoginError> {
    let access_token: AccessToken =
        input
            .access_token
            .parse()
            .map_err(|e: bitwarden_auth::AccessTokenInvalidError| {
                LoginError::AccessTokenInvalid(e.to_string())
            })?;

    if let Some(state_file) = &input.state_file
        && let Ok(organization_id) = load_tokens_from_state(client, state_file, &access_token).await
    {
        client
            .token_handler()
            .set_sm_login_method(ServiceAccountLoginMethod::AccessToken {
                access_token,
                organization_id,
                state_file: Some(state_file.to_path_buf()),
            });

        return Ok(AccessTokenLoginResponse::authenticated());
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
        let encryption_key = SymmetricCryptoKey::try_from(payload.encryption_key.clone())?;

        let access_token_jwt: JwtToken = r.access_token.parse()?;

        // This should always be Some() when logging in with an access token
        let organization_id: OrganizationId = access_token_jwt
            .organization
            .ok_or(LoginError::InvalidResponse)?
            .parse()
            .map_err(|_| LoginError::InvalidOrganizationId)?;

        if let Some(state_file) = &input.state_file {
            let state = ClientState::new(r.access_token.clone(), payload.encryption_key);
            _ = state::set(state_file, &access_token, state);
        }

        client
            .token_handler()
            .set_tokens(
                r.access_token.clone(),
                r.refresh_token.clone(),
                r.expires_in,
            )
            .await;

        // FIXME: [PM-18098] Replace with KeyStore API once set_symmetric_key is promoted
        #[allow(deprecated)]
        client
            .client()
            .internal
            .get_key_store()
            .context_mut()
            .set_symmetric_key(
                SymmetricKeySlotId::Organization(organization_id),
                encryption_key,
            )
            .expect("Mutable context");

        client
            .token_handler()
            .set_sm_login_method(ServiceAccountLoginMethod::AccessToken {
                access_token,
                organization_id,
                state_file: input.state_file.clone(),
            });
    }

    match response {
        IdentityTokenResponse::Payload(_r) => Ok(AccessTokenLoginResponse {
            authenticated: true,
            reset_master_password: false,
            force_password_reset: false,
            two_factor: None,
        }),
        _ => Ok(AccessTokenLoginResponse {
            authenticated: false,
            reset_master_password: false,
            force_password_reset: false,
            two_factor: None,
        }),
    }
}

async fn request_access_token(
    client: &SecretsManagerClient,
    access_token: &AccessToken,
) -> Result<IdentityTokenResponse, LoginError> {
    let config = client.client().internal.get_api_configurations();
    send_access_token_request(
        &config.identity_config,
        access_token.access_token_id,
        &access_token.client_secret,
    )
    .await
}

async fn load_tokens_from_state(
    client: &SecretsManagerClient,
    state_file: &Path,
    access_token: &AccessToken,
) -> Result<OrganizationId, LoginError> {
    let client_state =
        state::get(state_file, access_token).map_err(|_| LoginError::InvalidStateFile)?;

    let token: JwtToken = client_state.token.parse()?;

    if let Some(organization_id_str) = token.organization {
        let time_till_expiration = (token.exp as i64) - Utc::now().timestamp();

        if time_till_expiration > 0 {
            let organization_id: OrganizationId = organization_id_str
                .parse()
                .map_err(|_| LoginError::InvalidOrganizationId)?;

            let encryption_key = SymmetricCryptoKey::try_from(client_state.encryption_key)?;

            client
                .token_handler()
                .set_tokens(client_state.token, None, time_till_expiration as u64)
                .await;

            // FIXME: [PM-18098] Replace with KeyStore API once set_symmetric_key is promoted
            #[allow(deprecated)]
            client
                .client()
                .internal
                .get_key_store()
                .context_mut()
                .set_symmetric_key(
                    SymmetricKeySlotId::Organization(organization_id),
                    encryption_key,
                )
                .expect("Mutable context");

            return Ok(organization_id);
        }
    }

    Err(LoginError::InvalidStateFile)
}
