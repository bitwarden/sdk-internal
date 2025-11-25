use bitwarden_core::key_management::MasterPasswordAuthenticationData;
use serde::{Deserialize, Serialize};

use crate::{
    api::enums::GrantType,
    identity::{api::request::LoginApiRequest, login_via_password::PasswordLoginRequest},
};

/// Internal API request model for logging in via password.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PasswordLoginApiRequest {
    // // Common user token request payload
    // #[serde(flatten)]
    // user_login_api_request: UserLoginApiRequest,
    /// Bitwarden user email address
    #[serde(rename = "username")]
    pub email: String,

    /// Bitwarden user master password hash
    #[serde(rename = "password")]
    pub master_password_hash: String,
}

/// Converts a `PasswordLoginRequest` and `MasterPasswordAuthenticationData` into a
/// `PasswordLoginApiRequest` for making the API call.
impl From<(PasswordLoginRequest, MasterPasswordAuthenticationData)>
    for LoginApiRequest<PasswordLoginApiRequest>
{
    fn from(
        (request, master_password_authentication): (
            PasswordLoginRequest,
            MasterPasswordAuthenticationData,
        ),
    ) -> Self {
        // Create the PasswordLoginApiRequest with required fields
        let password_login_api_request = PasswordLoginApiRequest {
            email: request.email,
            master_password_hash: master_password_authentication
                .master_password_authentication_hash
                .to_string(),
        };

        // Create the UserLoginApiRequest with standard scopes configuration and return
        LoginApiRequest::new(
            request.login_request.client_id,
            GrantType::Password,
            request.login_request.device.device_type,
            request.login_request.device.device_identifier,
            request.login_request.device.device_name,
            request.login_request.device.device_push_token,
            password_login_api_request,
        )
    }
}
