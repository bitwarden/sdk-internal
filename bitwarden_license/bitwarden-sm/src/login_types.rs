use std::path::PathBuf;

use bitwarden_core::auth::login::response::two_factor::TwoFactorProviders;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    /// The available two factor authentication options. Present only when authentication fails
    /// due to requiring a second authentication factor.
    pub two_factor: Option<TwoFactorProviders>,
}

impl AccessTokenLoginResponse {
    /// Construct a fully-authenticated response with no two-factor challenge.
    pub fn authenticated() -> Self {
        Self {
            authenticated: true,
            reset_master_password: false,
            force_password_reset: false,
            two_factor: None,
        }
    }
}
