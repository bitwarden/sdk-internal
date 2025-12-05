use std::fmt::Debug;

use bitwarden_api_identity::models::KdfType;
use std::num::NonZeroU32;

use crate::identity::api::response::{LoginSuccessApiResponse, UserDecryptionOptionsApiResponse};

/// SDK response model for a successful login.
/// This is the model that will be exposed to consuming applications.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[derive(Debug)]
pub struct LoginSuccessResponse {
    /// The access token string.
    pub access_token: String,
    /// The duration in seconds until the token expires.
    pub expires_in: u64,
    /// The timestamp in milliseconds when the token expires.
    pub expires_at: i64,
    /// The scope of the access token.
    pub scope: String,
    /// The type of the token (typically "Bearer").
    pub token_type: String,
    /// The optional refresh token string.
    pub refresh_token: Option<String>,

    // TODO: port over docs from API response
    // but also RENAME things to be more clear.
    /// The user's encrypted private key.
    pub private_key: Option<String>,
    /// The user's encrypted symmetric key.
    pub key: Option<String>,
    /// Two-factor authentication token for future requests.
    pub two_factor_token: Option<String>,
    /// The key derivation function type.
    pub kdf: KdfType,
    /// The number of iterations for the key derivation function.
    pub kdf_iterations: NonZeroU32,
    /// Whether the user needs to reset their master password.
    pub reset_master_password: bool,
    /// Whether the user is forced to reset their password.
    pub force_password_reset: bool,
    /// Whether the API uses Key Connector.
    pub api_use_key_connector: Option<bool>,
    /// The URL for the Key Connector service.
    pub key_connector_url: Option<String>,
    /// User decryption options for the account.
    // pub user_decryption_options: UserDecryptionOptionsResponse,
}

impl From<LoginSuccessApiResponse> for LoginSuccessResponse {
    fn from(response: LoginSuccessApiResponse) -> Self {
        // We want to convert the expires_in from seconds to a millisecond timestamp to have a
        // concrete time the token will expire. This makes it easier to build logic around a
        // concrete time rather than a duration. We keep expires_in as well for backward
        // compatibility and convenience.
        let expires_at =
            chrono::Utc::now().timestamp_millis() + (response.expires_in * 1000) as i64;

        LoginSuccessResponse {
            access_token: response.access_token,
            expires_in: response.expires_in,
            expires_at,
            scope: response.scope,
            token_type: response.token_type,
            refresh_token: response.refresh_token,
            private_key: response.private_key,
            key: response.key,
            two_factor_token: response.two_factor_token,
            kdf: response.kdf,
            kdf_iterations: response.kdf_iterations,
            reset_master_password: response.reset_master_password,
            force_password_reset: response.force_password_reset,
            api_use_key_connector: response.api_use_key_connector,
            key_connector_url: response.key_connector_url,
            user_decryption_options: response.user_decryption_options,
        }
    }
}
