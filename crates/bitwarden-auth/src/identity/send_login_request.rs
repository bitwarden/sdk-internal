// Cleanest idea for allowing access to data needed for sending login requests
// Make this function accept the commmon model and flatten the specific

use bitwarden_core::client::ApiConfigurations;
use serde::{Serialize, de::DeserializeOwned};

use crate::identity::api_models::{
    login_request_header::LoginRequestHeader, request::UserLoginApiRequest,
};

/// A common function to send login requests to the Identity connect/token endpoint.
pub(crate) async fn send_login_request(
    api_configs: &ApiConfigurations,
    api_request: &UserLoginApiRequest<impl Serialize + DeserializeOwned + std::fmt::Debug>,
) -> Result<serde_json::Value, bitwarden_core::auth::login::LoginError> {
    let identity_config = &api_configs.identity_config;

    let url = format!("{}/connect/token", &identity_config.base_path);

    let device_type_header = LoginRequestHeader::DeviceType(api_request.device_type);

    let mut request = identity_config
        .client
        .post(format!("{}/connect/token", &identity_config.base_path))
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

    // return empty json for now
    Ok(serde_json::json!({}))
}
