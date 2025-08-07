use bitwarden_core::Client;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::send_access::{
    access_token_response::AuthApiError,
    internal::{
        SendAccessTokenApiErrorResponse, SendAccessTokenApiSuccessResponse,
        SendAccessTokenRequestPayload,
    },
    SendAccessTokenError, SendAccessTokenRequest, SendAccessTokenResponse,
};

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
    ///
    /// # Arguments
    /// * `request` - The request containing the necessary information to obtain a token.
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

        let request = configurations
            .identity
            .client
            .post(format!(
                "{}/connect/token",
                &configurations.identity.base_path
            ))
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

        let response = request.send().await?;

        // handle success and error responses
        // If the response is 200, we can deserialize it into SendAccessToken
        if response.status().is_success() {
            let send_access_token: SendAccessTokenApiSuccessResponse = response.json().await?;
            return Ok(send_access_token.into());
        }

        // // If the response is not successful, we should handle the error.
        // if response.status().is_client_error() || response.status().is_server_error() {
        //     let error: SendAccessTokenApiErrorResponse = response.json().await?;

        //     return Err(SendAccessTokenError::Response(error));
        // }

        // // If we reach here, it means we received an unexpected response.
        // Err(SendAccessTokenError::UnexpectedStatus(response.status()))

        let err_response = response.json::<SendAccessTokenApiErrorResponse>().await?;
        Err(SendAccessTokenError::Response(err_response))

        // match response.json::<SendAccessTokenApiErrorResponse>().await {
        //     Ok(err) => Err(SendAccessTokenError::Response(err)),
        //     Err(e) => Err(SendAccessTokenError::Api(AuthApiError(e))),
        // }
    }
}
