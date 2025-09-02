//! Integration tests for send access feature

use bitwarden_auth::{
    send_access::{
        api::{
            SendAccessTokenApiErrorResponse, SendAccessTokenInvalidGrantError,
            SendAccessTokenInvalidRequestError,
        },
        SendAccessClient, SendAccessCredentials, SendAccessTokenError, SendAccessTokenRequest,
        SendAccessTokenResponse, SendEmailCredentials, SendPasswordCredentials,
    },
    AuthClientExt,
};
use bitwarden_core::{Client as CoreClient, ClientSettings, DeviceType};
use bitwarden_test::start_api_mock;
use wiremock::{
    matchers::{self, body_string_contains},
    Mock, MockServer, ResponseTemplate,
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
    async fn request_send_access_token_success() {
        // Create a mock success response
        let raw_success = serde_json::json!({
            "access_token": "token",
            "token_type": "bearer",
            "expires_in":   3600,
            "scope": "api.send"
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
                "application/x-www-form-urlencoded; charset=utf-8",
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
            .and(body_string_contains("grant_type=send_access"))
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
    use bitwarden_auth::send_access::SendEmailOtpCredentials;

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
            send_access_credentials: Some(SendAccessCredentials::Password(password_credentials)),
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
            send_access_credentials: Some(SendAccessCredentials::EmailOtp(email_otp_credentials)),
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
                        send_access_error_type: Some(SendAccessTokenInvalidGrantError::OtpInvalid),
                        error_description: Some(error_description),
                    }
                );
            }
            other => panic!("expected Response variant, got {:?}", other),
        }
    }
}
