use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::send_access::{
    SendAccessTokenError, SendAccessTokenRequest, SendAccessTokenResponse,
    access_token_response::UnexpectedIdentityError,
    api::{
        SendAccessTokenApiErrorResponse, SendAccessTokenApiSuccessResponse,
        SendAccessTokenRequestPayload,
    },
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
        let url = format!(
            "{}/connect/token",
            &configurations.identity_config.base_path
        );

        let request: reqwest::RequestBuilder = configurations
            .identity_config
            .client
            .post(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::CACHE_CONTROL, "no-store")
            .form(&payload);

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

#[cfg(test)]
mod tests {
    use bitwarden_core::{Client as CoreClient, ClientSettings, DeviceType};
    use bitwarden_test::start_api_mock;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{self, body_string_contains},
    };

    use crate::{
        AuthClientExt,
        api::enums::{GrantType, Scope},
        send_access::{
            SendAccessClient, SendAccessCredentials, SendAccessTokenError, SendAccessTokenRequest,
            SendAccessTokenResponse, SendEmailCredentials, SendEmailOtpCredentials,
            SendPasswordCredentials, UnexpectedIdentityError,
            api::{
                SendAccessTokenApiErrorResponse, SendAccessTokenInvalidGrantError,
                SendAccessTokenInvalidRequestError,
            },
        },
    };

    fn make_send_client(mock_server: &MockServer) -> SendAccessClient {
        let settings = ClientSettings {
            identity_url: format!("http://{}/identity", mock_server.address()),
            api_url: format!("http://{}/api", mock_server.address()),
            user_agent: "Bitwarden Rust-SDK [TEST]".into(),
            device_type: DeviceType::SDK,
        };
        let core_client = CoreClient::new(Some(settings));
        core_client.auth_new().send_access()
    }

    mod request_send_access_token_success_tests {

        use super::*;

        #[tokio::test]
        async fn request_send_access_token_anon_send_success() {
            let scope_value = serde_json::to_value(Scope::ApiSendAccess).unwrap();
            let scope_str = scope_value.as_str().unwrap();

            let grant_type_value = serde_json::to_value(GrantType::SendAccess).unwrap();
            let grant_type_str = grant_type_value.as_str().unwrap();

            // Create a mock success response
            let raw_success = serde_json::json!({
                "access_token": "token",
                "token_type": "bearer",
                "expires_in":   3600,
                "scope": scope_str
            });

            // Construct the real Request type
            let req = SendAccessTokenRequest {
                send_id: "test_send_id".into(),
                send_access_credentials: None, // No credentials for this test
            };

            let mock = Mock::given(matchers::method("POST"))
                .and(matchers::path("identity/connect/token"))
                // expect the headers we set in the client
                .and(matchers::header(
                    reqwest::header::CONTENT_TYPE.as_str(),
                    "application/x-www-form-urlencoded",
                ))
                .and(matchers::header(
                    reqwest::header::ACCEPT.as_str(),
                    "application/json",
                ))
                .and(matchers::header(
                    reqwest::header::CACHE_CONTROL.as_str(),
                    "no-store",
                ))
                // expect the body to contain the fields we set in our payload object
                .and(body_string_contains("client_id=send"))
                .and(body_string_contains(format!(
                    "grant_type={}",
                    grant_type_str
                )))
                .and(body_string_contains(format!("scope={}", scope_str)))
                .and(body_string_contains(format!("send_id={}", req.send_id)))
                // respond with the mock success response
                .respond_with(ResponseTemplate::new(200).set_body_json(raw_success));

            // Spin up a server and register mock with it
            let (mock_server, _api_config) = start_api_mock(vec![mock]).await;

            // Create a send access client
            let send_access_client = make_send_client(&mock_server);

            let token: SendAccessTokenResponse = send_access_client
                .request_send_access_token(req)
                .await
                .unwrap();

            assert_eq!(token.token, "token");
            assert!(token.expires_at > 0);
        }

        #[tokio::test]
        async fn request_send_access_token_password_protected_send_success() {
            let scope_value = serde_json::to_value(Scope::ApiSendAccess).unwrap();
            let scope_str = scope_value.as_str().unwrap();

            let grant_type_value = serde_json::to_value(GrantType::SendAccess).unwrap();
            let grant_type_str = grant_type_value.as_str().unwrap();

            // Create a mock success response
            let raw_success = serde_json::json!({
                "access_token": "token",
                "token_type": "bearer",
                "expires_in":   3600,
                "scope": scope_str
            });

            let password_hash_b64 = "valid-hash";

            let password_credentials = SendPasswordCredentials {
                password_hash_b64: password_hash_b64.into(),
            };

            let req = SendAccessTokenRequest {
                send_id: "valid-send-id".into(),
                send_access_credentials: Some(SendAccessCredentials::Password(
                    password_credentials,
                )),
            };

            let mock = Mock::given(matchers::method("POST"))
                .and(matchers::path("identity/connect/token"))
                // expect the headers we set in the client
                .and(matchers::header(
                    reqwest::header::CONTENT_TYPE.as_str(),
                    "application/x-www-form-urlencoded",
                ))
                .and(matchers::header(
                    reqwest::header::ACCEPT.as_str(),
                    "application/json",
                ))
                .and(matchers::header(
                    reqwest::header::CACHE_CONTROL.as_str(),
                    "no-store",
                ))
                // expect the body to contain the fields we set in our payload object
                .and(body_string_contains("client_id=send"))
                .and(body_string_contains(format!(
                    "grant_type={}",
                    grant_type_str
                )))
                .and(body_string_contains(format!("scope={}", scope_str)))
                .and(body_string_contains(format!("send_id={}", req.send_id)))
                .and(body_string_contains(format!(
                    "password_hash_b64={}",
                    password_hash_b64
                )))
                // respond with the mock success response
                .respond_with(ResponseTemplate::new(200).set_body_json(raw_success));

            // Spin up a server and register mock with it
            let (mock_server, _api_config) = start_api_mock(vec![mock]).await;

            // Create a send access client
            let send_access_client = make_send_client(&mock_server);

            let token: SendAccessTokenResponse = send_access_client
                .request_send_access_token(req)
                .await
                .unwrap();

            assert_eq!(token.token, "token");
            assert!(token.expires_at > 0);
        }

        #[tokio::test]
        async fn request_send_access_token_email_otp_protected_send_success() {
            let scope_value = serde_json::to_value(Scope::ApiSendAccess).unwrap();
            let scope_str = scope_value.as_str().unwrap();

            let grant_type_value = serde_json::to_value(GrantType::SendAccess).unwrap();
            let grant_type_str = grant_type_value.as_str().unwrap();

            // Create a mock success response
            let raw_success = serde_json::json!({
                "access_token": "token",
                "token_type": "bearer",
                "expires_in":   3600,
                "scope": scope_str
            });

            let email = "valid@email.com";
            let otp: &str = "valid_otp";

            let email_otp_credentials = SendEmailOtpCredentials {
                email: email.into(),
                otp: otp.into(),
            };

            let req = SendAccessTokenRequest {
                send_id: "valid-send-id".into(),
                send_access_credentials: Some(SendAccessCredentials::EmailOtp(
                    email_otp_credentials,
                )),
            };

            let mock = Mock::given(matchers::method("POST"))
                .and(matchers::path("identity/connect/token"))
                // expect the headers we set in the client
                .and(matchers::header(
                    reqwest::header::CONTENT_TYPE.as_str(),
                    "application/x-www-form-urlencoded",
                ))
                .and(matchers::header(
                    reqwest::header::ACCEPT.as_str(),
                    "application/json",
                ))
                .and(matchers::header(
                    reqwest::header::CACHE_CONTROL.as_str(),
                    "no-store",
                ))
                // expect the body to contain the fields we set in our payload object
                .and(body_string_contains("client_id=send"))
                .and(body_string_contains(format!(
                    "grant_type={}",
                    grant_type_str
                )))
                .and(body_string_contains(format!("scope={}", scope_str)))
                .and(body_string_contains(format!("send_id={}", req.send_id)))
                .and(body_string_contains("email=valid%40email.com"))
                .and(body_string_contains(format!("otp={}", otp)))
                // respond with the mock success response
                .respond_with(ResponseTemplate::new(200).set_body_json(raw_success));

            // Spin up a server and register mock with it
            let (mock_server, _api_config) = start_api_mock(vec![mock]).await;

            // Create a send access client
            let send_access_client = make_send_client(&mock_server);

            let token: SendAccessTokenResponse = send_access_client
                .request_send_access_token(req)
                .await
                .unwrap();

            assert_eq!(token.token, "token");
            assert!(token.expires_at > 0);
        }
    }

    mod request_send_access_token_invalid_request_tests {
        use super::*;

        #[tokio::test]
        async fn request_send_access_token_invalid_request_send_id_required_error() {
            // Create a mock error response
            let error_description = "send_id is required.".into();
            let raw_error = serde_json::json!({
                "error": "invalid_request",
                "error_description": error_description,
                "send_access_error_type": "send_id_required"
            });

            // Register the mock for the request
            let mock = Mock::given(matchers::method("POST"))
                .and(matchers::path("identity/connect/token"))
                .respond_with(ResponseTemplate::new(400).set_body_json(raw_error));

            // Spin up a server and register mock with it
            let (mock_server, _api_config) = start_api_mock(vec![mock]).await;

            // Create a send access client
            let send_access_client = make_send_client(&mock_server);

            // Construct the request without a send_id to trigger an error
            let req = SendAccessTokenRequest {
                send_id: "".into(),
                send_access_credentials: None, // No credentials for this test
            };

            let result = send_access_client.request_send_access_token(req).await;

            assert!(result.is_err());

            let err = result.unwrap_err();
            match err {
                SendAccessTokenError::Expected(api_err) => {
                    assert_eq!(
                        api_err,
                        SendAccessTokenApiErrorResponse::InvalidRequest {
                            send_access_error_type: Some(
                                SendAccessTokenInvalidRequestError::SendIdRequired
                            ),
                            error_description: Some(error_description),
                        }
                    );
                }
                other => panic!("expected Response variant, got {:?}", other),
            }
        }

        #[tokio::test]
        async fn request_send_access_token_invalid_request_password_hash_required_error() {
            // Create a mock error response
            let error_description = "password_hash_b64 is required.".into();
            let raw_error = serde_json::json!({
                "error": "invalid_request",
                "error_description": error_description,
                "send_access_error_type": "password_hash_b64_required"
            });

            // Register the mock for the request
            let mock = Mock::given(matchers::method("POST"))
                .and(matchers::path("identity/connect/token"))
                .respond_with(ResponseTemplate::new(400).set_body_json(raw_error));

            // Spin up a server and register mock with it
            let (mock_server, _api_config) = start_api_mock(vec![mock]).await;

            // Create a send access client
            let send_access_client = make_send_client(&mock_server);

            // Construct the request with a send_id but no credentials to trigger the error
            let req = SendAccessTokenRequest {
                send_id: "test_send_id".into(),
                send_access_credentials: None, // No credentials for this test
            };

            let result = send_access_client.request_send_access_token(req).await;

            assert!(result.is_err());

            let err = result.unwrap_err();
            match err {
                SendAccessTokenError::Expected(api_err) => {
                    assert_eq!(
                        api_err,
                        SendAccessTokenApiErrorResponse::InvalidRequest {
                            send_access_error_type: Some(
                                SendAccessTokenInvalidRequestError::PasswordHashB64Required
                            ),
                            error_description: Some(error_description),
                        }
                    );
                }
                other => panic!("expected Response variant, got {:?}", other),
            }
        }

        #[tokio::test]
        async fn request_send_access_token_invalid_request_email_required_error() {
            // Create a mock error response
            let error_description = "email is required.".into();
            let raw_error = serde_json::json!({
                "error": "invalid_request",
                "error_description": error_description,
                "send_access_error_type": "email_required"
            });

            // Register the mock for the request
            let mock = Mock::given(matchers::method("POST"))
                .and(matchers::path("identity/connect/token"))
                .respond_with(ResponseTemplate::new(400).set_body_json(raw_error));

            // Spin up a server and register mock with it
            let (mock_server, _api_config) = start_api_mock(vec![mock]).await;

            // Create a send access client
            let send_access_client = make_send_client(&mock_server);

            // Construct the request with a send_id but no credentials to trigger the error
            let req = SendAccessTokenRequest {
                send_id: "test_send_id".into(),
                send_access_credentials: None, // No credentials for this test
            };

            let result = send_access_client.request_send_access_token(req).await;

            assert!(result.is_err());

            let err = result.unwrap_err();
            match err {
                SendAccessTokenError::Expected(api_err) => {
                    assert_eq!(
                        api_err,
                        SendAccessTokenApiErrorResponse::InvalidRequest {
                            send_access_error_type: Some(
                                SendAccessTokenInvalidRequestError::EmailRequired
                            ),
                            error_description: Some(error_description),
                        }
                    );
                }
                other => panic!("expected Response variant, got {:?}", other),
            }
        }

        #[tokio::test]
        async fn request_send_access_token_invalid_request_email_otp_required_error() {
            // Create a mock error response
            let error_description =
                "email and otp are required. An OTP has been sent to the email address provided."
                    .into();
            let raw_error = serde_json::json!({
                "error": "invalid_request",
                "error_description": error_description,
                "send_access_error_type": "email_and_otp_required_otp_sent"
            });

            // Create the mock for the request
            let mock = Mock::given(matchers::method("POST"))
                .and(matchers::path("identity/connect/token"))
                .respond_with(ResponseTemplate::new(400).set_body_json(raw_error));

            // Spin up a server and register mock with it
            let (mock_server, _api_config) = start_api_mock(vec![mock]).await;

            // Create a send access client
            let send_access_client = make_send_client(&mock_server);

            // Construct the request with a send_id and email credential
            let email_credentials = SendEmailCredentials {
                email: "test@example.com".into(),
            };

            let req = SendAccessTokenRequest {
                send_id: "test_send_id".into(),
                send_access_credentials: Some(SendAccessCredentials::Email(email_credentials)),
            };

            let result = send_access_client.request_send_access_token(req).await;

            assert!(result.is_err());

            let err = result.unwrap_err();
            match err {
                SendAccessTokenError::Expected(api_err) => {
                    assert_eq!(
                        api_err,
                        SendAccessTokenApiErrorResponse::InvalidRequest {
                            send_access_error_type: Some(
                                SendAccessTokenInvalidRequestError::EmailAndOtpRequiredOtpSent
                            ),
                            error_description: Some(error_description),
                        }
                    );
                }
                other => panic!("expected Response variant, got {:?}", other),
            }
        }
    }

    mod request_send_access_token_invalid_grant_tests {

        use super::*;

        #[tokio::test]
        async fn request_send_access_token_invalid_grant_invalid_send_id_error() {
            // Create a mock error response
            let error_description = "send_id is invalid.".into();
            let raw_error = serde_json::json!({
                "error": "invalid_grant",
                "error_description": error_description,
                "send_access_error_type": "send_id_invalid"
            });

            // Create the mock for the request
            let mock = Mock::given(matchers::method("POST"))
                .and(matchers::path("identity/connect/token"))
                .respond_with(ResponseTemplate::new(400).set_body_json(raw_error));

            // Spin up a server and register mock with it
            let (mock_server, _api_config) = start_api_mock(vec![mock]).await;

            // Create a send access client
            let send_access_client = make_send_client(&mock_server);

            // Construct the request without a send_id to trigger an error
            let req = SendAccessTokenRequest {
                send_id: "invalid-send-id".into(),
                send_access_credentials: None, // No credentials for this test
            };

            let result = send_access_client.request_send_access_token(req).await;

            assert!(result.is_err());

            let err = result.unwrap_err();
            match err {
                SendAccessTokenError::Expected(api_err) => {
                    // Now assert the inner enum:
                    assert_eq!(
                        api_err,
                        SendAccessTokenApiErrorResponse::InvalidGrant {
                            send_access_error_type: Some(
                                SendAccessTokenInvalidGrantError::SendIdInvalid
                            ),
                            error_description: Some(error_description),
                        }
                    );
                }
                other => panic!("expected Response variant, got {:?}", other),
            }
        }

        #[tokio::test]
        async fn request_send_access_token_invalid_grant_invalid_password_hash_error() {
            // Create a mock error response
            let error_description = "password_hash_b64 is invalid.".into();
            let raw_error = serde_json::json!({
                "error": "invalid_grant",
                "error_description": error_description,
                "send_access_error_type": "password_hash_b64_invalid"
            });

            // Create the mock for the request
            let mock = Mock::given(matchers::method("POST"))
                .and(matchers::path("identity/connect/token"))
                .respond_with(ResponseTemplate::new(400).set_body_json(raw_error));

            // Spin up a server and register mock with it
            let (mock_server, _api_config) = start_api_mock(vec![mock]).await;

            // Create a send access client
            let send_access_client = make_send_client(&mock_server);

            // Construct the request
            let password_credentials = SendPasswordCredentials {
                password_hash_b64: "invalid-hash".into(),
            };

            let req = SendAccessTokenRequest {
                send_id: "valid-send-id".into(),
                send_access_credentials: Some(SendAccessCredentials::Password(
                    password_credentials,
                )),
            };

            let result = send_access_client.request_send_access_token(req).await;

            assert!(result.is_err());

            let err = result.unwrap_err();
            match err {
                SendAccessTokenError::Expected(api_err) => {
                    // Now assert the inner enum:
                    assert_eq!(
                        api_err,
                        SendAccessTokenApiErrorResponse::InvalidGrant {
                            send_access_error_type: Some(
                                SendAccessTokenInvalidGrantError::PasswordHashB64Invalid
                            ),
                            error_description: Some(error_description),
                        }
                    );
                }
                other => panic!("expected Response variant, got {:?}", other),
            }
        }

        #[tokio::test]
        async fn request_send_access_token_invalid_grant_invalid_email_error() {
            // Create a mock error response
            let error_description = "email is invalid.".into();
            let raw_error = serde_json::json!({
                "error": "invalid_grant",
                "error_description": error_description,
                "send_access_error_type": "email_invalid"
            });

            // Register the mock for the request
            let mock = Mock::given(matchers::method("POST"))
                .and(matchers::path("identity/connect/token"))
                .respond_with(ResponseTemplate::new(400).set_body_json(raw_error));

            // Spin up a server and register mock with it
            let (mock_server, _api_config) = start_api_mock(vec![mock]).await;

            // Create a send access client
            let send_access_client = make_send_client(&mock_server);

            // Construct the request
            let email_credentials = SendEmailCredentials {
                email: "invalid-email".into(),
            };
            let req = SendAccessTokenRequest {
                send_id: "valid-send-id".into(),
                send_access_credentials: Some(SendAccessCredentials::Email(email_credentials)),
            };

            let result = send_access_client.request_send_access_token(req).await;

            assert!(result.is_err());

            let err = result.unwrap_err();
            match err {
                SendAccessTokenError::Expected(api_err) => {
                    // Now assert the inner enum:
                    assert_eq!(
                        api_err,
                        SendAccessTokenApiErrorResponse::InvalidGrant {
                            send_access_error_type: Some(
                                SendAccessTokenInvalidGrantError::EmailInvalid
                            ),
                            error_description: Some(error_description),
                        }
                    );
                }
                other => panic!("expected Response variant, got {:?}", other),
            }
        }

        #[tokio::test]
        async fn request_send_access_token_invalid_grant_invalid_otp_error() {
            // Create a mock error response
            let error_description = "otp is invalid.".into();
            let raw_error = serde_json::json!({
                "error": "invalid_grant",
                "error_description": error_description,
                "send_access_error_type": "otp_invalid"
            });

            // Create the mock for the request
            let mock = Mock::given(matchers::method("POST"))
                .and(matchers::path("identity/connect/token"))
                .respond_with(ResponseTemplate::new(400).set_body_json(raw_error));

            // Spin up a server and register mock with it
            let (mock_server, _api_config) = start_api_mock(vec![mock]).await;

            // Create a send access client
            let send_access_client = make_send_client(&mock_server);

            // Construct the request
            let email_otp_credentials = SendEmailOtpCredentials {
                email: "valid@email.com".into(),
                otp: "valid_otp".into(),
            };
            let req = SendAccessTokenRequest {
                send_id: "valid-send-id".into(),
                send_access_credentials: Some(SendAccessCredentials::EmailOtp(
                    email_otp_credentials,
                )),
            };

            let result = send_access_client.request_send_access_token(req).await;

            assert!(result.is_err());

            let err = result.unwrap_err();
            match err {
                SendAccessTokenError::Expected(api_err) => {
                    // Now assert the inner enum:
                    assert_eq!(
                        api_err,
                        SendAccessTokenApiErrorResponse::InvalidGrant {
                            send_access_error_type: Some(
                                SendAccessTokenInvalidGrantError::OtpInvalid
                            ),
                            error_description: Some(error_description),
                        }
                    );
                }
                other => panic!("expected Response variant, got {:?}", other),
            }
        }
    }

    mod request_send_access_token_unexpected_error_tests {

        use super::*;

        async fn run_case(status_code: u16, reason: &str) {
            let mock = Mock::given(matchers::method("POST"))
                .and(matchers::path("identity/connect/token"))
                .respond_with(ResponseTemplate::new(status_code));

            let (mock_server, _api_config) = start_api_mock(vec![mock]).await;
            let send_access_client = make_send_client(&mock_server);

            let req = SendAccessTokenRequest {
                send_id: "test_send_id".into(),
                send_access_credentials: None,
            };

            let result = send_access_client.request_send_access_token(req).await;

            assert!(result.is_err());

            let err = result.expect_err(&format!(
                "expected Err for status {} {} against http://{}/identity/connect/token",
                status_code,
                reason,
                mock_server.address()
            ));

            match err {
                SendAccessTokenError::Unexpected(api_err) => {
                    let expected = UnexpectedIdentityError(format!(
                        "Received response status {} {} against http://{}/identity/connect/token",
                        status_code,
                        reason,
                        mock_server.address()
                    ));
                    assert_eq!(api_err, expected, "mismatch for status {}", status_code);
                }
                other => panic!("expected Unexpected variant, got {:?}", other),
            }
        }

        #[tokio::test]
        async fn request_send_access_token_unexpected_statuses() {
            let cases = [
                // 4xx (client errors) — excluding 400 Bad Request as we handle those as expected
                // errors.
                (401, "Unauthorized"),
                (402, "Payment Required"),
                (403, "Forbidden"),
                (404, "Not Found"),
                (405, "Method Not Allowed"),
                (406, "Not Acceptable"),
                (407, "Proxy Authentication Required"),
                (408, "Request Timeout"),
                (409, "Conflict"),
                (410, "Gone"),
                (411, "Length Required"),
                (412, "Precondition Failed"),
                (413, "Payload Too Large"),
                (414, "URI Too Long"),
                (415, "Unsupported Media Type"),
                (416, "Range Not Satisfiable"),
                (417, "Expectation Failed"),
                (421, "Misdirected Request"),
                (422, "Unprocessable Entity"),
                (423, "Locked"),
                (424, "Failed Dependency"),
                (425, "Too Early"),
                (426, "Upgrade Required"),
                (428, "Precondition Required"),
                (429, "Too Many Requests"),
                (431, "Request Header Fields Too Large"),
                (451, "Unavailable For Legal Reasons"),
                // 5xx (server errors)
                (500, "Internal Server Error"),
                (501, "Not Implemented"),
                (502, "Bad Gateway"),
                (503, "Service Unavailable"),
                (504, "Gateway Timeout"),
                (505, "HTTP Version Not Supported"),
                (506, "Variant Also Negotiates"),
                (507, "Insufficient Storage"),
                (508, "Loop Detected"),
                (510, "Not Extended"),
                (511, "Network Authentication Required"),
            ];

            for (code, reason) in cases {
                run_case(code, reason).await;
            }
        }
    }
}
