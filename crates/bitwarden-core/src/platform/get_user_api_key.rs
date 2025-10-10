//! Get the user's API key.
//!
//! This module provides the functionality to get the user's API key.
//!
//! <div class="warning">
//!
//! This code is currently unused and unmaintained!
//!
//! - Prior to use it should be reviewed and tested.
//! - Code should move to the appropriate code owner.
//! - Secret verification should be extracted as it's a common pattern for multiple requests.
//!
//! </div>

use std::sync::Arc;

use bitwarden_api_api::models::{ApiKeyResponseModel, SecretVerificationRequestModel};
use bitwarden_crypto::{CryptoError, HashPurpose, MasterKey};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::SecretVerificationRequest;
use crate::{
    ApiError, Client, MissingFieldError, NotAuthenticatedError,
    client::{LoginMethod, UserLoginMethod},
    require,
};

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum UserApiKeyError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    NotAuthenticated(#[from] NotAuthenticatedError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error("Unsupported login method")]
    UnsupportedLoginMethod,
}

/// Get the user's API key.
pub(crate) async fn get_user_api_key(
    client: &Client,
    input: &SecretVerificationRequest,
) -> Result<UserApiKeyResponse, UserApiKeyError> {
    info!("Getting Api Key");
    debug!("{input:?}");

    let auth_settings = get_login_method(client)?;
    let config = client.internal.get_api_configurations().await;

    let request = build_secret_verification_request(&auth_settings, input)?;
    let response = config
        .api_client
        .accounts_api()
        .api_key(Some(request))
        .await
        .map_err(ApiError::from)?;
    UserApiKeyResponse::process_response(response)
}

fn get_login_method(client: &Client) -> Result<Arc<LoginMethod>, NotAuthenticatedError> {
    client
        .internal
        .get_login_method()
        .ok_or(NotAuthenticatedError)
}

/// Build the secret verification request.
fn build_secret_verification_request(
    login_method: &LoginMethod,
    input: &SecretVerificationRequest,
) -> Result<SecretVerificationRequestModel, UserApiKeyError> {
    if let LoginMethod::User(UserLoginMethod::Username { email, kdf, .. }) = login_method {
        let master_password_hash = input
            .master_password
            .as_ref()
            .map(|p| {
                let master_key = MasterKey::derive(p, email, kdf)?;

                Ok::<String, CryptoError>(
                    master_key
                        .derive_master_key_hash(p.as_bytes(), HashPurpose::ServerAuthorization)
                        .to_string(),
                )
            })
            .transpose()?;
        Ok(SecretVerificationRequestModel {
            master_password_hash,
            otp: input.otp.as_ref().cloned(),
            secret: None,
            auth_request_access_code: None,
        })
    } else {
        Err(UserApiKeyError::UnsupportedLoginMethod)
    }
}

/// The response from the server when requesting the user's API key.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserApiKeyResponse {
    /// The user's API key, which represents the client_secret portion of an oauth request.
    api_key: String,
}

impl UserApiKeyResponse {
    pub(crate) fn process_response(
        response: ApiKeyResponseModel,
    ) -> Result<UserApiKeyResponse, UserApiKeyError> {
        let api_key = require!(response.api_key);
        Ok(UserApiKeyResponse { api_key })
    }
}
