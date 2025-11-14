use serde::Serialize;

use crate::identity::{
    IdentityClient, api_models::request::UserTokenApiRequest,
    login_via_password::PasswordLoginRequest,
};

/// API request model for logging in via password.
#[derive(Serialize, Debug)]
#[allow(dead_code)]
struct PasswordLoginApiRequest {
    // Common user token request payload
    #[serde(flatten)]
    user_token_api_request: UserTokenApiRequest,

    /// Bitwarden user email address
    #[serde(rename = "username")]
    pub email: String,

    /// Bitwarden user master password hash
    #[serde(rename = "password")]
    pub master_password_hash: String,
}

impl IdentityClient {
    // TODO: add implementation for login via password
    // pub async fn login_via_password(&self, request: PasswordLoginRequest) {
    //     // Implementation goes here
    // }
}
