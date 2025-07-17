use crate::auth::{
    send_access::{
        models::{SendAccessToken, SendAccessTokenPayload},
        requests::SendAccessTokenRequest,
    },
    AuthClient,
};

pub struct SendTokenApiService {
    pub(crate) auth_client: AuthClient,
}

// see send_identity_connect_request for example
impl SendTokenApiService {
    /// Requests a new access token.
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
            .body(serde_qs::to_string(&payload).expect("Serialize should be infallible"));

        let response = request.send().await?;

        // TODO: Would need to handle 200 response
        // response.status()
        // if 200 can do response.json to get type SendAccessTokenResponse
        // if not 200, handle error response convert into error type
        // Will have to create error enum

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
