use std::fmt::Debug;

use bitwarden_api_api::models::MasterPasswordPolicyResponseModel;
use bitwarden_api_identity::models::KdfType;
use std::num::NonZeroU32;

use crate::identity::{
    api::response::{LoginSuccessApiResponse, UserDecryptionOptionsApiResponse},
    models::UserDecryptionOptionsResponse,
};

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
    /// We calculate this for more convenient token expiration handling.
    pub expires_at: i64,

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

    /// The user key wrapped user private key.
    /// Note: previously known as "private_key".
    pub user_key_wrapped_user_private_key: Option<String>,

    /// The master key wrapped user key.
    /// Note: previously known as "key".
    pub master_key_wrapped_user_key: Option<String>,

    /// Two-factor authentication token for future requests.
    pub two_factor_token: Option<String>,

    /// The key derivation function type.
    pub kdf: KdfType,

    /// Master key derivation function iterations
    pub kdf_iterations: NonZeroU32,

    /// Indicates whether an admin has reset the user's master password,
    /// requiring them to set a new password upon next login.
    pub force_password_reset: bool,

    /// Indicates whether the user uses Key Connector and if the client should have a locally
    /// configured Key Connector URL in their environment.
    /// Note: This is currently only applicable for client_credential grant type logins and
    /// is only expected to be relevant for the CLI
    pub api_use_key_connector: Option<bool>,

    /// The user's decryption options for unlocking their vault.
    pub user_decryption_options: UserDecryptionOptionsResponse,

    // TODO: there isn't a top level domain model for this. Create one? or keep as is?
    /// If the user is subject to an organization master password policy,
    /// this field contains the requirements of that policy.
    pub master_password_policy: Option<MasterPasswordPolicyResponseModel>,
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
            user_key_encrypted_user_private_key: response.private_key,
            master_key_encrypted_user_key: response.key,
            two_factor_token: response.two_factor_token,
            kdf: response.kdf,
            kdf_iterations: response.kdf_iterations,
            force_password_reset: response.force_password_reset,
            api_use_key_connector: response.api_use_key_connector,
            user_decryption_options: response.user_decryption_options,
        }
    }
}
