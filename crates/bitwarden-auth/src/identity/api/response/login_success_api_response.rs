use bitwarden_api_api::models::MasterPasswordPolicyResponseModel;
use bitwarden_api_identity::models::KdfType;
use serde::{Deserialize, Serialize};

use crate::identity::api::response::UserDecryptionOptionsApiResponse;

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
    // We send down uppercase fields today so we have to map them accordingly +
    // we add aliases for deserialization flexibility.
    /// The user key wrapped user private key
    #[serde(rename = "PrivateKey", alias = "privateKey")]
    pub private_key: Option<String>,

    /// The master key wrapped user key.
    #[serde(rename = "Key", alias = "key")]
    pub key: Option<String>,

    /// Two factor remember me token to be used for future requests
    /// to bypass 2FA prompts for a limited time.
    #[serde(rename = "TwoFactorToken", alias = "twoFactorToken")]
    pub two_factor_token: Option<String>,

    /// Master key derivation function type
    #[serde(rename = "Kdf", alias = "kdf")]
    pub kdf: KdfType,

    // TODO: ensure we convert to NonZeroU32 for the SDK model
    // for any Some values
    /// Master key derivation function iterations
    #[serde(rename = "KdfIterations", alias = "kdfIterations")]
    pub kdf_iterations: Option<i32>,

    /// Master key derivation function memory
    #[serde(rename = "KdfMemory", alias = "kdfMemory")]
    pub kdf_memory: Option<i32>,

    /// Master key derivation function parallelism
    #[serde(rename = "KdfParallelism", alias = "kdfParallelism")]
    pub kdf_parallelism: Option<i32>,

    /// Indicates whether an admin has reset the user's master password,
    /// requiring them to set a new password upon next login.
    #[serde(rename = "ForcePasswordReset", alias = "forcePasswordReset")]
    pub force_password_reset: Option<bool>,

    /// Indicates whether the user uses Key Connector and if the client should have a locally
    /// configured Key Connector URL in their environment.
    /// Note: This is currently only applicable for client_credential grant type logins and
    /// is only expected to be relevant for the CLI
    #[serde(rename = "ApiUseKeyConnector", alias = "apiUseKeyConnector")]
    pub api_use_key_connector: Option<bool>,

    /// The user's decryption options for their vault.
    #[serde(rename = "UserDecryptionOptions", alias = "userDecryptionOptions")]
    pub user_decryption_options: Option<UserDecryptionOptionsApiResponse>,

    /// If the user is subject to an organization master password policy,
    /// this field contains the requirements of that policy.
    #[serde(rename = "MasterPasswordPolicy", alias = "masterPasswordPolicy")]
    pub master_password_policy: Option<MasterPasswordPolicyResponseModel>,
}
