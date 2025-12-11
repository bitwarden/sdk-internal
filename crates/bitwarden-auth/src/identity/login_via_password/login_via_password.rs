use bitwarden_core::key_management::MasterPasswordAuthenticationData;

use crate::identity::{
    IdentityClient,
    api::{request::LoginApiRequest, send_login_request},
    login_via_password::{PasswordLoginApiRequest, PasswordLoginRequest},
    models::{LoginError, LoginResponse},
};

impl IdentityClient {
    /// Logs in a user via their email and master password.
    ///
    /// This function derives the necessary master password authentication data
    /// using the provided prelogin data, constructs the appropriate API request,
    /// and sends the request to the Identity connect/token endpoint to log the user in.
    pub async fn login_via_password(
        &self,
        request: PasswordLoginRequest,
    ) -> Result<LoginResponse, LoginError> {
        // use request password prelogin data to derive master password authentication data:
        let master_password_authentication: Result<
            MasterPasswordAuthenticationData,
            bitwarden_core::key_management::MasterPasswordError,
        > = MasterPasswordAuthenticationData::derive(
            &request.password,
            &request.prelogin_response.kdf,
            &request.email,
        );

        // construct API request
        let api_request: LoginApiRequest<PasswordLoginApiRequest> =
            (request, master_password_authentication.unwrap()).into();

        // make API call to login endpoint with api_request
        let api_configs = self.client.internal.get_api_configurations().await;

        let response = send_login_request(&api_configs, &api_request).await;

        // if success, we must validate that user decryption options are present as if they are
        // missing we cannot proceed with unlocking the user's vault.

        // TODO: figure out how to handle errors.
        todo!()
    }
}
