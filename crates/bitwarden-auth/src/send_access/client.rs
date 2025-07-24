use bitwarden_core::Client;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::send_access::{
    internal::{
        SendAccessTokenApiErrorResponse, SendAccessTokenApiSuccessResponse,
        SendAccessTokenRequestPayload,
    },
    SendAccessTokenRequest, SendAccessTokenResponse,
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
    ) -> Result<SendAccessTokenResponse, bitwarden_core::ApiError> {
        // Convert the request to the appropriate format for sending.
        let payload: SendAccessTokenRequestPayload = request.into();

        // When building other identity token requests, we used to send credentials: "include" on non-web clients or if the
        // env had a base URL. See client's apiService.getCredentials() for example. However, it doesn't
        // seem necessary for this request, so we are not including it here.
        // If needed, we can revisit this and add it back in.

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
            let send_access_token: SendAccessTokenApiSuccessResponse = response
                .json()
                .await
                // the ? try operator here will return and propagate the error if it occurs
                // this narrows from Result<SendAccessTokenResponse, reqwest::Error> to
                // Result<SendAccessTokenResponse, bitwarden_core::ApiError>
                .map_err(bitwarden_core::ApiError::from)?;
            return Ok(send_access_token.into());
        }

        // If the response is not successful, we should handle the error.
        if response.status().is_client_error() || response.status().is_server_error() {
            let error: SendAccessTokenApiErrorResponse = response
                .json()
                .await
                .map_err(bitwarden_core::ApiError::from)?;

            // If we want to create a custom error to return we can map the error response to our own error type
            // by building the error type and then adding a from trait implementation for it.
            // The way that we do this typically is by creating a new enum that
            // represents the bitwarden_core::ApiError and my new error type.

            // Map the error description to our enum
            // let error_enum: SendTokenApiErrorDescription =
            //     serde_json::from_str(&error_description).unwrap_or_else(|_| {
            //         SendTokenApiErrorDescription::UnknownError
            //     });

            // return Err(bitwarden_core::ApiError::SendTokenApiError(error_enum));
        }

        todo!("Implement error handling");
    }
}
