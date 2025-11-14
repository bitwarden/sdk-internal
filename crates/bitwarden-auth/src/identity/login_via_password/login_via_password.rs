use bitwarden_core::key_management::MasterPasswordAuthenticationData;
use serde::Serialize;

use crate::{
    api::enums::GrantType,
    identity::{
        IdentityClient, api_models::request::UserTokenApiRequest,
        login_via_password::PasswordLoginRequest,
    },
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

/// Converts a `PasswordLoginRequest` and `MasterPasswordAuthenticationData` into a
/// `PasswordLoginApiRequest` for making the API call.
impl From<(PasswordLoginRequest, MasterPasswordAuthenticationData)> for PasswordLoginApiRequest {
    fn from(
        (request, master_password_authentication): (
            PasswordLoginRequest,
            MasterPasswordAuthenticationData,
        ),
    ) -> Self {
        // Create the UserTokenApiRequest with standard scopes configuration
        let user_token_api_request = UserTokenApiRequest::new(
            request.login_request.client_id,
            GrantType::Password,
            request.login_request.device.device_type,
            request.login_request.device.device_identifier,
            request.login_request.device.device_name,
        );

        Self {
            user_token_api_request,
            email: request.email,
            master_password_hash: master_password_authentication
                .master_password_authentication_hash
                .to_string(),
        }
    }
}

impl IdentityClient {
    // #![allow(dead_code)]
    // #![allow(unused_imports)]
    // #![allow(unused_variables)]
    // #![allow(missing_docs)]
    // pub async fn login_via_password(&self, request: PasswordLoginRequest) {
    //     // use request password prelogin data to derive master password authentication data:
    //     let master_password_authentication: Result<
    //         MasterPasswordAuthenticationData,
    //         bitwarden_core::key_management::MasterPasswordError,
    //     > = MasterPasswordAuthenticationData::derive( &request.password,
    //     > &request.prelogin_data.kdf, &request.email,
    //     );

    //     // construct API request
    //     let api_request: PasswordLoginApiRequest =
    //         (request, master_password_authentication.unwrap()).into();

    //     // make API call to login endpoint with api_request
    //     let config = self.client.internal.get_api_configurations().await;

    //     // TODO: next week talk through implementing the actual API call and handling the
    // response     // The existing password flow uses a base send_identity_connect_request
    // which is re-used     // across multiple login methods. Should we do the same here?
    // }
}
