//! Integration tests for send access feature

use bitwarden_auth::{
    send_access::{
        api::{SendAccessTokenApiErrorResponse, SendAccessTokenInvalidRequestError},
        SendAccessClient, SendAccessCredentials, SendAccessTokenError, SendAccessTokenRequest,
        SendAccessTokenResponse, SendEmailCredentials,
    },
    AuthClientExt,
};
use bitwarden_core::{Client as CoreClient, ClientSettings, DeviceType};
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

#[tokio::test]
async fn request_send_access_token_success() {
    // spin up mock server
    let mock_server = MockServer::start().await;

    // Create a send access client
    let send_access_client = make_send_client(&mock_server);

    // Construct the real Request type
    let req = SendAccessTokenRequest {
        send_id: "test_send_id".into(),
        send_access_credentials: None, // No credentials for this test
    };

    // Create a mock success response
    let raw_success = serde_json::json!({
        "access_token": "token",
        "token_type": "bearer",
        "expires_in":   3600,
        "scope": "api.send"
    });

    // Register the mock for the request
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

    // Register the mock with the server
    mock_server.register(mock).await;

    let token: SendAccessTokenResponse = send_access_client
        .request_send_access_token(req)
        .await
        .unwrap();

    assert_eq!(token.token, "token");
    assert!(token.expires_at > 0);
}

#[tokio::test]
async fn request_send_access_token_invalid_request_send_id_required_error() {
    // spin up mock server
    let mock_server = MockServer::start().await;

    // Create a send access client
    let send_access_client = make_send_client(&mock_server);

    // Construct the request without a send_id to trigger an error
    let req = SendAccessTokenRequest {
        send_id: "".into(),
        send_access_credentials: None, // No credentials for this test
    };

    // Create a mock error response
    let raw_error = serde_json::json!({
        "error": "invalid_request",
        "error_description": "send_id is required."
    });

    // Register the mock for the request
    let mock = Mock::given(matchers::method("POST"))
        .and(matchers::path("identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(raw_error));

    // Register the mock with the server
    mock_server.register(mock).await;

    let result = send_access_client.request_send_access_token(req).await;

    assert!(result.is_err());

    let err = result.unwrap_err();
    match err {
        SendAccessTokenError::Response(api_err) => {
            // Now assert the inner enum:
            assert_eq!(
                api_err,
                SendAccessTokenApiErrorResponse::InvalidRequest(Some(
                    SendAccessTokenInvalidRequestError::SendIdRequired
                ))
            );
        }
        other => panic!("expected Response variant, got {:?}", other),
    }
}

#[tokio::test]
async fn request_send_access_token_invalid_request_password_hash_required_error() {
    // spin up mock server
    let mock_server = MockServer::start().await;

    // Create a send access client
    let send_access_client = make_send_client(&mock_server);

    // Construct the request with a send_id but no credentials to trigger the error
    let req = SendAccessTokenRequest {
        send_id: "test_send_id".into(),
        send_access_credentials: None, // No credentials for this test
    };

    // Create a mock error response
    let raw_error = serde_json::json!({
        "error": "invalid_request",
        "error_description": "password_hash is required."
    });

    // Register the mock for the request
    let mock = Mock::given(matchers::method("POST"))
        .and(matchers::path("identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(raw_error));

    // Register the mock with the server
    mock_server.register(mock).await;

    let result = send_access_client.request_send_access_token(req).await;

    assert!(result.is_err());

    let err = result.unwrap_err();
    match err {
        SendAccessTokenError::Response(api_err) => {
            // Now assert the inner enum:
            assert_eq!(
                api_err,
                SendAccessTokenApiErrorResponse::InvalidRequest(Some(
                    SendAccessTokenInvalidRequestError::PasswordHashRequired
                ))
            );
        }
        other => panic!("expected Response variant, got {:?}", other),
    }
}

#[tokio::test]
async fn request_send_access_token_invalid_request_email_required_error() {
    // spin up mock server
    let mock_server = MockServer::start().await;

    // Create a send access client
    let send_access_client = make_send_client(&mock_server);

    // Construct the request with a send_id but no credentials to trigger the error
    let req = SendAccessTokenRequest {
        send_id: "test_send_id".into(),
        send_access_credentials: None, // No credentials for this test
    };

    // Create a mock error response
    let raw_error = serde_json::json!({
        "error": "invalid_request",
        "error_description": "Email is required."
    });

    // Register the mock for the request
    let mock = Mock::given(matchers::method("POST"))
        .and(matchers::path("identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(raw_error));

    // Register the mock with the server
    mock_server.register(mock).await;

    let result = send_access_client.request_send_access_token(req).await;

    assert!(result.is_err());

    let err = result.unwrap_err();
    match err {
        SendAccessTokenError::Response(api_err) => {
            // Now assert the inner enum:
            assert_eq!(
                api_err,
                SendAccessTokenApiErrorResponse::InvalidRequest(Some(
                    SendAccessTokenInvalidRequestError::EmailRequired
                ))
            );
        }
        other => panic!("expected Response variant, got {:?}", other),
    }
}

#[tokio::test]
async fn request_send_access_token_invalid_request_email_otp_required_error() {
    // spin up mock server
    let mock_server = MockServer::start().await;

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

    // Create a mock error response
    let raw_error = serde_json::json!({
        "error": "invalid_request",
        "error_description": "Email and OTP are required. An OTP has been sent to the email address provided."
    });

    // Register the mock for the request
    let mock = Mock::given(matchers::method("POST"))
        .and(matchers::path("identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(raw_error));

    // Register the mock with the server
    mock_server.register(mock).await;

    let result = send_access_client.request_send_access_token(req).await;

    assert!(result.is_err());

    let err = result.unwrap_err();
    match err {
        SendAccessTokenError::Response(api_err) => {
            // Now assert the inner enum:
            assert_eq!(
                api_err,
                SendAccessTokenApiErrorResponse::InvalidRequest(Some(
                    SendAccessTokenInvalidRequestError::EmailAndOtpRequiredOtpSent
                ))
            );
        }
        other => panic!("expected Response variant, got {:?}", other),
    }
}
