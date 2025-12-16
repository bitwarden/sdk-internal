use serde::{Serialize, de::DeserializeOwned};

use crate::identity::{
    api::{
        login_request_header::LoginRequestHeader,
        request::LoginApiRequest,
        response::{LoginErrorApiResponse, LoginSuccessApiResponse},
    },
    models::{LoginResponse, LoginSuccessResponse},
};

// TODO: should this be on the LoginClient struct instead of being a standalone function?
/// A common function to send login requests to the Identity connect/token endpoint.
/// Returns a common success model which has already been converted from the API response,
/// or a common error model representing the login error which allows for conversion to specific error types
/// based on the login method used.
pub(crate) async fn send_login_request(
    identity_config: &bitwarden_api_identity::apis::configuration::Configuration,
    api_request: &LoginApiRequest<impl Serialize + DeserializeOwned + std::fmt::Debug>,
) -> Result<LoginResponse, LoginErrorApiResponse> {
    let url: String = format!("{}/connect/token", &identity_config.base_path);

    let device_type_header: LoginRequestHeader =
        LoginRequestHeader::DeviceType(api_request.device_type);

    let request: reqwest::RequestBuilder = identity_config
        .client
        .post(url)
        .header(reqwest::header::ACCEPT, "application/json")
        // Add custom device type header
        .header(
            device_type_header.header_name(),
            device_type_header.header_value(),
        )
        // per OAuth2 spec recommendation for token requests (https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1)
        // we include no-cache headers to prevent browser caching sensistive token requests / responses.
        .header(reqwest::header::CACHE_CONTROL, "no-store")
        .header(reqwest::header::PRAGMA, "no-cache")
        // TODO: investigate missing headers from api.service implementation like:
        // .header("Bitwarden-Client-Name")
        // Bitwarden-Client-Name
        // Bitwarden-Client-Version
        // Bitwarden-Package-Type
        // User-Agent
        // TODO: investigate if I have to worry about credentials here
        // use form to encode as application/x-www-form-urlencoded
        .form(&api_request);

    let response: reqwest::Response = request.send().await?;

    let response_status = response.status();

    if response_status.is_success() {
        let login_success_api_response: LoginSuccessApiResponse = response.json().await?;

        let login_success_response: LoginSuccessResponse = login_success_api_response.try_into()?;

        let login_response = LoginResponse::Authenticated(login_success_response);

        return Ok(login_response);
    }

    let login_error_api_response: LoginErrorApiResponse = response.json().await?;

    Err(login_error_api_response)
}
