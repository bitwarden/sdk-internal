// Cleanest idea for allowing access to data needed for sending login requests
// Make this function accept the commmon model and flatten the specific

use bitwarden_core::client::ApiConfigurations;
use serde::{Serialize, de::DeserializeOwned};

use crate::identity::api::{
    login_request_header::LoginRequestHeader,
    request::LoginApiRequest,
    response::{LoginErrorApiResponse, LoginSuccessApiResponse},
};

/// A common function to send login requests to the Identity connect/token endpoint.
pub(crate) async fn send_login_request(
    api_configs: &ApiConfigurations,
    api_request: &LoginApiRequest<impl Serialize + DeserializeOwned + std::fmt::Debug>,
) -> Result<LoginSuccessApiResponse, LoginErrorApiResponse> {
    let identity_config = &api_configs.identity_config;

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
        // we must include "no-store" cache control
        .header(reqwest::header::CACHE_CONTROL, "no-store")
        // use form to encode as application/x-www-form-urlencoded
        .form(&api_request);

    let response: reqwest::Response = request.send().await?;

    let response_status = response.status();

    if response_status.is_success() {
        let login_success_api_response: LoginSuccessApiResponse = response.json().await?;

        // TODO: define LoginSuccessResponse model in SDK layer and add into trait from
        // LoginSuccessApiResponse to convert between API model and SDK model

        return Ok(login_success_api_response);
    }

    // Handle error response
    let login_error_api_response: LoginErrorApiResponse = response.json().await?;

    Err(login_error_api_response)
}
