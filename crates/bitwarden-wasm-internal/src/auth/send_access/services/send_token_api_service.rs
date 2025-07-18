use crate::auth::{
    send_access::{
        models::{SendAccessToken, SendAccessTokenPayload},
        requests::SendAccessTokenRequest,
        responses::{SendAccessTokenErrorResponse, SendAccessTokenResponse},
    },
    AuthClient,
};

pub struct SendTokenApiService {
    pub(crate) auth_client: AuthClient,
}

// see send_identity_connect_request for example
impl SendTokenApiService {
    /// Requests a new send access token.
    ///
    /// # Arguments
    /// * `request` - The request containing the necessary information to obtain a token.
    pub async fn request_send_access_token(
        &self,
        request: SendAccessTokenRequest,
    ) -> Result<SendAccessToken, bitwarden_core::ApiError> {
        // Convert the request to the appropriate format for sending.
        let payload: SendAccessTokenPayload = request.into();

        // When building other identity token requests, we used to send credentials: "include" on non-web clients or if the
        // env had a base URL. See client's apiService.getCredentials() for example. However, it doesn't
        // seem necessary for this request, so we are not including it here.
        // If needed, we can revisit this and add it back in.

        let configurations = self
            .auth_client
            .client
            .internal
            .get_api_configurations()
            .await;

        let mut request = configurations
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
            let send_access_token: SendAccessTokenResponse = response
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
            let error: SendAccessTokenErrorResponse = response
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

        todo!("Implement the request logic using reqwest or similar library");
    }
}

//   async requestSendAccessToken(
//     request: SendAccessTokenRequest,
//   ): Promise<SendAccessToken | SendTokenApiError> {
//     const payload = request.toIdentityTokenPayload();

//     const headers = new Headers({
//       "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
//       Accept: "application/json",
//     });

//     const env = await firstValueFrom(this.environmentService.environment$);

//     const req = new Request(env.getIdentityUrl() + "/connect/token", {
//       method: "POST",
//       body: new URLSearchParams(payload as any),
//       headers: headers,
//       credentials: credentials,
//       cache: "no-store",
//     });

//     const response = await this.apiService.fetch(req);

//     // TODO: Determine if we need the isJsonResponse check here like API service
//     let responseJson: any;
//     try {
//       responseJson = await response.json();
//     } catch {
//       // Only expected for server runtime exceptions or maybe CORS errors
//       return "json-parse-error";
//     }

//     if (response.status === 200) {
//       const sendAccessToken = SendAccessToken.fromResponseData(responseJson);
//       return sendAccessToken;
//     }

//     if (response.status === 400 && responseJson?.error) {
//       return this.mapTokenResponseToError(responseJson.error, responseJson.error_description);
//     }

//     // TODO: maybe log this error?
//     return "unknown-error";
//   }

// private mapTokenResponseToError(error: string, errorDescription?: string): SendTokenApiError {
//     const errorDescKey = errorDescription ?? "";
//     switch (error) {
//       case "invalid_request": {
//         return INVALID_REQUEST_ERROR_MAPPING[errorDescKey] || "invalid-request";
//       }

//       case "invalid_grant": {
//         return INVALID_GRANT_ERROR_MAPPING[errorDescKey] || "invalid-grant";
//       }

//       default:
//         return "unknown-error";
//     }
//   }

// TODO: write integration test for this service.
// create new auth client and then try calling this method.
