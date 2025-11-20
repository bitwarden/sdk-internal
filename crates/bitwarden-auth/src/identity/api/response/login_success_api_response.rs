use bitwarden_api_identity::models::KdfType;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;

use crate::identity::api::response::UserDecryptionOptionsResponse;

/// API response model for a successful login via the Identity API.
/// OAuth 2.0 Successful Response RFC reference: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.1>
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub(crate) struct LoginSuccessApiResponse {
    /// The access token string.
    pub access_token: String,
    /// The duration in seconds until the token expires.
    pub expires_in: u64,
    /// The scope of the access token.
    /// OAuth 2.0 RFC reference: <https://datatracker.ietf.org/doc/html/rfc6749#section-3.3>
    pub scope: String,

    /// The type of the token.
    /// This will be "Bearer" for send access tokens.
    /// OAuth 2.0 RFC reference: <https://datatracker.ietf.org/doc/html/rfc6749#section-7.1>
    pub token_type: String,

    /// The optional refresh token string.
    /// This token can be used to obtain new access tokens when the current one expires.
    pub refresh_token: Option<String>,

    // Custom Bitwarden connect/token response fields:
    #[serde(rename = "privateKey", alias = "PrivateKey")]
    pub(crate) private_key: Option<String>,
    #[serde(alias = "Key")]
    pub(crate) key: Option<String>,
    #[serde(rename = "twoFactorToken")]
    two_factor_token: Option<String>,
    #[serde(alias = "Kdf")]
    kdf: KdfType,
    #[serde(
        rename = "kdfIterations",
        alias = "KdfIterations",
        default = "bitwarden_crypto::default_pbkdf2_iterations"
    )]
    kdf_iterations: NonZeroU32,

    #[serde(rename = "resetMasterPassword", alias = "ResetMasterPassword")]
    pub reset_master_password: bool,
    #[serde(rename = "forcePasswordReset", alias = "ForcePasswordReset")]
    pub force_password_reset: bool,
    #[serde(rename = "apiUseKeyConnector", alias = "ApiUseKeyConnector")]
    api_use_key_connector: Option<bool>,
    #[serde(rename = "keyConnectorUrl", alias = "KeyConnectorUrl")]
    key_connector_url: Option<String>,

    #[serde(rename = "userDecryptionOptions", alias = "UserDecryptionOptions")]
    pub(crate) user_decryption_options: Option<UserDecryptionOptionsResponse>,
}
