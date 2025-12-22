use bitwarden_api_api::models::{MasterPasswordPolicyResponseModel, PrivateKeysResponseModel};
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
    /// Deprecated in favor of the `AccountKeys` field but still present for backward compatibility.
    /// and we can't expose AccountKeys in our LoginSuccessResponse until we get a PrivateKeysResponseModel
    /// SDK response model from KM with WASM / uniffi support.
    #[serde(rename = "PrivateKey", alias = "privateKey")]
    pub private_key: Option<String>,

    /// The user's asymmetric encryption keys and signature keys
    #[serde(rename = "AccountKeys", alias = "accountKeys")]
    pub account_keys: Option<PrivateKeysResponseModel>,

    /// The master key wrapped user key.
    #[deprecated(note = "Use `user_decryption_options.master_password_unlock` instead")]
    #[serde(rename = "Key", alias = "key")]
    pub key: Option<String>,

    /// Two factor remember me token to be used for future requests
    /// to bypass 2FA prompts for a limited time.
    #[serde(rename = "TwoFactorToken", alias = "twoFactorToken")]
    pub two_factor_token: Option<String>,

    /// Master key derivation function type
    #[deprecated(note = "Use `user_decryption_options.master_password_unlock` instead")]
    #[serde(rename = "Kdf", alias = "kdf")]
    pub kdf: Option<KdfType>,

    /// Master key derivation function iterations
    #[deprecated(note = "Use `user_decryption_options.master_password_unlock` instead")]
    #[serde(rename = "KdfIterations", alias = "kdfIterations")]
    pub kdf_iterations: Option<i32>,

    /// Master key derivation function memory
    #[deprecated(note = "Use `user_decryption_options.master_password_unlock` instead")]
    #[serde(rename = "KdfMemory", alias = "kdfMemory")]
    pub kdf_memory: Option<i32>,

    /// Master key derivation function parallelism
    #[deprecated(note = "Use `user_decryption_options.master_password_unlock` instead")]
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
