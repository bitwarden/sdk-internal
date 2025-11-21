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
    /// The user's user key encrypted private key
    #[serde(rename = "privateKey", alias = "PrivateKey")]
    pub(crate) private_key: Option<String>,

    /// The user's master key encrypted user key.
    #[serde(alias = "Key")]
    pub(crate) key: Option<String>,

    /// Two factor remember me token to be used for future requests to bypass 2FA prompts
    /// for a limited time.
    #[serde(rename = "twoFactorToken")]
    two_factor_token: Option<String>,

    /// Master key derivation function type
    #[serde(alias = "Kdf")]
    kdf: KdfType,
    #[serde(
        rename = "kdfIterations",
        alias = "KdfIterations",
        default = "bitwarden_crypto::default_pbkdf2_iterations"
    )]
    /// Master key derivation function iterations
    kdf_iterations: NonZeroU32,

    // TODO: can we just not include this as it should be deprecated
    #[serde(rename = "resetMasterPassword", alias = "ResetMasterPassword")]
    pub reset_master_password: bool,

    // TODO: do we want to pass this along unchanged or should we convert to
    // an enum for ForceSetPasswordReason like we have in clients?
    /// If an admin has forced a password reset for the user, this will be true.
    #[serde(rename = "forcePasswordReset", alias = "ForcePasswordReset")]
    pub force_password_reset: bool,

    ///
    #[serde(rename = "apiUseKeyConnector", alias = "ApiUseKeyConnector")]
    api_use_key_connector: Option<bool>,
    #[serde(rename = "keyConnectorUrl", alias = "KeyConnectorUrl")]
    key_connector_url: Option<String>,

    #[serde(rename = "userDecryptionOptions", alias = "UserDecryptionOptions")]
    pub(crate) user_decryption_options: Option<UserDecryptionOptionsResponse>,
}
