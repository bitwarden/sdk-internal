use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::send_access::{
    access_token_response::UnexpectedIdentityError,
    api::{
        SendAccessTokenApiErrorResponse, SendAccessTokenApiSuccessResponse,
        SendAccessTokenRequestPayload,
    },
    SendAccessTokenError, SendAccessTokenRequest, SendAccessTokenResponse,
};

/// The `SendAccessClient` is used to interact with the Bitwarden API to get send access tokens.
#[derive(Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct SendAccessClient {
    pub(crate) client: Client,
}

impl SendAccessClient {
    pub(crate) fn new(client: Client) -> Self {
        Self { client }
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl SendAccessClient {
    /// Requests a new send access token.
    pub async fn request_send_access_token(
        &self,
        request: SendAccessTokenRequest,
    ) -> Result<SendAccessTokenResponse, SendAccessTokenError> {
        // Convert the request to the appropriate format for sending.
        let payload: SendAccessTokenRequestPayload = request.into();

        // When building other identity token requests, we used to send credentials: "include" on
        // non-web clients or if the env had a base URL. See client's
        // apiService.getCredentials() for example. However, it doesn't seem necessary for
        // this request, so we are not including it here. If needed, we can revisit this and
        // add it back in.

        let configurations = self.client.internal.get_api_configurations().await;

        // save off url in variable for re-use
        let url = format!("{}/connect/token", &configurations.identity.base_path);

        let request: reqwest::RequestBuilder = configurations
            .identity
            .client
            .post(&url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded; charset=utf-8",
            )
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::CACHE_CONTROL, "no-store")
            // We can use `serde_urlencoded` to serialize the payload into a URL-encoded string
            // because we don't have complex nested structures in the payload.
            // If we had nested structures, we have to use serde_qs::to_string instead.
            .body(serde_urlencoded::to_string(&payload).expect("Serialize should be infallible"));

        // Because of the ? operator, any errors from sending the request are automatically
        // wrapped in SendAccessTokenError::Unexpected as an UnexpectedIdentityError::Reqwest
        // variant and returned.
        // note: we had to manually built a trait to map reqwest::Error to SendAccessTokenError.
        let response: reqwest::Response = request.send().await?;

        let response_status = response.status();

        // handle success and error responses
        // If the response is 2xx, we can deserialize it into SendAccessToken
        if response_status.is_success() {
            let send_access_token: SendAccessTokenApiSuccessResponse = response.json().await?;
            return Ok(send_access_token.into());
        }

        let err_response = match response.json::<SendAccessTokenApiErrorResponse>().await {
            // If the response is a 400 with a specific error type, we can deserialize it into
            // SendAccessTokenApiErrorResponse and then convert it into
            // SendAccessTokenError::Expected later on.
            Ok(err) => err,
            Err(_) => {
                // This handles any 4xx that aren't specifically handled above
                // as well as any other non-2xx responses (5xx, etc).

                let error_string = format!(
                    "Received response status {} against {}",
                    response_status, url
                );

                return Err(SendAccessTokenError::Unexpected(UnexpectedIdentityError(
                    error_string,
                )));
            }
        };

        Err(SendAccessTokenError::Expected(err_response))
    }
}
