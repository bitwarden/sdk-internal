use serde::{Serialize, de::DeserializeOwned};

use crate::identity::{
    api::{
        request::LoginApiRequest,
        response::{LoginErrorApiResponse, LoginSuccessApiResponse},
    },
    models::{LoginResponse, LoginSuccessResponse},
};

/// A common function to send login requests to the Identity connect/token endpoint.
/// Returns a common success model which has already been converted from the API response,
/// or a common error model representing the login error which allows for conversion to specific
/// error types based on the login method used.
pub(crate) async fn send_login_request(
    identity_config: &bitwarden_api_identity::apis::configuration::Configuration,
    api_request: &LoginApiRequest<impl Serialize + DeserializeOwned + std::fmt::Debug>,
) -> Result<LoginResponse, LoginErrorApiResponse> {
    let url: String = format!("{}/connect/token", &identity_config.base_path);

    let request: reqwest_middleware::RequestBuilder = identity_config
        .client
        .post(url)
        .header(reqwest::header::ACCEPT, "application/json")
        // per OAuth2 spec recommendation for token requests (https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1)
        // we include no-cache headers to prevent browser caching sensitive token requests /
        // responses.
        .header(reqwest::header::CACHE_CONTROL, "no-store")
        .header(reqwest::header::PRAGMA, "no-cache")
        // If we run into authN issues, it could be due to https://bitwarden.atlassian.net/browse/PM-29974
        // not being done yet. In the clients repo, we add credentials: "include" for all
        // non web clients or any self hosted deployments. However, we want to solve that at the
        // core client layer and not here.
        // use form to encode as application/x-www-form-urlencoded
        .form(&api_request);

    let response: reqwest::Response = request.send().await?;

    let response_status = response.status();

    if response_status.is_success() {
        let login_success_api_response: LoginSuccessApiResponse = response.json().await?;

        let login_success_response: LoginSuccessResponse = login_success_api_response.try_into()?;

        let login_response = LoginResponse::Authenticated(login_success_response);

        return Ok(login_response);
    }

    let login_error_api_response: LoginErrorApiResponse = response.json().await?;

    Err(login_error_api_response)
}

#[cfg(test)]
mod tests {
    //! # Testing Philosophy for `send_login_request`
    //!
    //! This test module focuses on **HTTP/protocol layer concerns** for the low-level
    //! `send_login_request` utility function. These tests verify that the HTTP machinery
    //! works correctly, not comprehensive error scenario testing.
    //!
    //! ## What These Tests Cover
    //!
    //! 1. **HTTP Success Path** - Response parsing and conversion to domain types
    //! 2. **OAuth2 Error Discrimination** - Different OAuth2 error types are correctly deserialized
    //!    and preserved (invalid_grant, invalid_request, invalid_client)
    //! 3. **Error Propagation Mechanism** - One representative test confirming that lower-layer
    //!    errors (reqwest, serde) are converted to `LoginErrorApiResponse`
    //! 4. **Response Validation** - One test for incomplete data (different code path from JSON
    //!    parsing failures)
    //! 5. **HTTP Headers** - Verification that required headers are set correctly
    //!
    //! ## What These Tests DON'T Cover
    //!
    //! **Comprehensive error scenario testing** is intentionally done at the integration
    //! level in `login_via_password_impl.rs` (and other login method implementations).
    //! This includes:
    //! - Multiple network error types (DNS, timeout, connection refused, etc.)
    //! - Multiple malformed response types (empty body, invalid JSON, wrong content-type, etc.)
    //! - Unexpected HTTP status codes
    //! - Domain-specific error conversion and handling
    //!
    //! ## Rationale
    //!
    //! `send_login_request` is a **shared utility** used by multiple login methods.
    //! Testing every error permutation here would:
    //! - Create maintenance burden (updating tests in multiple places)
    //! - Provide false confidence (many tests covering the same code paths)
    //! - Obscure the function's actual responsibilities
    //!
    //! Instead, we test **what this function is responsible for** (HTTP mechanics and
    //! error type discrimination), and rely on integration tests to verify end-to-end
    //! error handling through the complete stack.

    use bitwarden_api_identity::apis::configuration::Configuration;
    use bitwarden_core::DeviceType;
    use bitwarden_test::start_api_mock;
    use wiremock::{Mock, ResponseTemplate, matchers};

    use super::*;
    use crate::{
        api::enums::GrantType,
        identity::{api::request::LoginApiRequest, models::LoginResponse},
    };

    // Test constants
    const TEST_CLIENT_ID: &str = "test-client";
    const TEST_DEVICE_ID: &str = "test-device-id";
    const TEST_DEVICE_NAME: &str = "Test Device";

    // Simple mock login mechanism fields for testing
    #[derive(Serialize, serde::Deserialize, Debug)]
    struct MockLoginFields {
        username: String,
        password: String,
    }

    // ==================== Test Helper Functions ====================

    fn create_test_login_request() -> LoginApiRequest<MockLoginFields> {
        LoginApiRequest::new(
            TEST_CLIENT_ID.to_string(),
            GrantType::Password,
            DeviceType::SDK,
            TEST_DEVICE_ID.to_string(),
            TEST_DEVICE_NAME.to_string(),
            None,
            MockLoginFields {
                username: "user@example.com".to_string(),
                password: "hashed-password".to_string(),
            },
        )
    }

    fn create_identity_config(mock_server: &wiremock::MockServer) -> Configuration {
        let reqwest_client = reqwest::Client::new();
        let client = reqwest_middleware::ClientBuilder::new(reqwest_client).build();

        Configuration {
            base_path: format!("http://{}/identity", mock_server.address()),
            client,
            ..Default::default()
        }
    }

    fn add_standard_request_matchers(mock_builder: wiremock::MockBuilder) -> wiremock::MockBuilder {
        mock_builder
            .and(matchers::header(
                reqwest::header::ACCEPT.as_str(),
                "application/json",
            ))
            .and(matchers::header(
                reqwest::header::CACHE_CONTROL.as_str(),
                "no-store",
            ))
            .and(matchers::header(
                reqwest::header::PRAGMA.as_str(),
                "no-cache",
            ))
    }

    fn create_mock_success_response() -> serde_json::Value {
        serde_json::json!({
            "access_token": "test_access_token_abc123",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "test_refresh_token_xyz789",
            "scope": "api offline_access",
            "Key": "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=",
            "PrivateKey": "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=",
            "Kdf": 0,
            "KdfIterations": 600000,
            "ForcePasswordReset": false,
            "MasterPasswordPolicy": {
                "Object": "masterPasswordPolicy"
            },
            "UserDecryptionOptions": {
                "HasMasterPassword": true,
                "MasterPasswordUnlock": {
                    "Kdf": {
                        "KdfType": 0,
                        "Iterations": 600000
                    },
                    "MasterKeyEncryptedUserKey": "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=",
                    "Salt": "user@example.com"
                },
                "Object": "userDecryptionOptions"
            }
        })
    }

    fn assert_login_success_response(login_response: &LoginResponse) {
        match login_response {
            LoginResponse::Authenticated(success) => {
                assert_eq!(success.access_token, "test_access_token_abc123");
                assert_eq!(success.token_type, "Bearer");
                assert_eq!(success.expires_in, 3600);
                assert_eq!(success.scope, "api offline_access");
                assert_eq!(
                    success.refresh_token,
                    Some("test_refresh_token_xyz789".to_string())
                );
                assert_eq!(success.two_factor_token, None);
                assert_eq!(success.force_password_reset, Some(false));
                assert_eq!(success.api_use_key_connector, None);

                // Verify user decryption options
                let decryption_options = &success.user_decryption_options;
                assert!(decryption_options.master_password_unlock.is_some());
                let mp_unlock = decryption_options.master_password_unlock.as_ref().unwrap();
                assert_eq!(
                    mp_unlock.master_key_wrapped_user_key.to_string(),
                    "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE="
                );
                assert_eq!(mp_unlock.salt, "user@example.com");

                // Verify master password policy is present
                assert!(success.master_password_policy.is_some());
            }
        }
    }

    // ==================== Success Tests ====================

    #[tokio::test]
    async fn test_send_login_request_success() {
        let success_response = create_mock_success_response();
        let mock = add_standard_request_matchers(
            Mock::given(matchers::method("POST")).and(matchers::path("/identity/connect/token")),
        )
        .respond_with(ResponseTemplate::new(200).set_body_json(success_response));

        let (mock_server, _) = start_api_mock(vec![mock]).await;
        let identity_config = create_identity_config(&mock_server);
        let login_request = create_test_login_request();

        let result = send_login_request(&identity_config, &login_request).await;

        assert!(result.is_ok(), "Expected success response");
        let login_response = result.unwrap();
        assert_login_success_response(&login_response);
    }

    // ==================== OAuth2 Error Tests ====================

    #[tokio::test]
    async fn test_send_login_request_invalid_credentials() {
        let error_response = serde_json::json!({
            "error": "invalid_grant",
            "error_description": "invalid_username_or_password"
        });

        let mock = Mock::given(matchers::method("POST"))
            .and(matchers::path("/identity/connect/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(error_response));

        let (mock_server, _) = start_api_mock(vec![mock]).await;
        let identity_config = create_identity_config(&mock_server);
        let login_request = create_test_login_request();

        let result = send_login_request(&identity_config, &login_request).await;

        assert!(result.is_err(), "Expected error response");
        let error = result.unwrap_err();
        match error {
            LoginErrorApiResponse::OAuth2Error(oauth_error) => {
                assert!(matches!(
                    oauth_error,
                    crate::identity::api::response::OAuth2ErrorApiResponse::InvalidGrant { .. }
                ));
            }
            _ => panic!("Expected OAuth2Error variant"),
        }
    }

    #[tokio::test]
    async fn test_send_login_request_invalid_request() {
        let error_response = serde_json::json!({
            "error": "invalid_request",
            "error_description": "Missing required parameter: password"
        });

        let mock = Mock::given(matchers::method("POST"))
            .and(matchers::path("/identity/connect/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(error_response));

        let (mock_server, _) = start_api_mock(vec![mock]).await;
        let identity_config = create_identity_config(&mock_server);
        let login_request = create_test_login_request();

        let result = send_login_request(&identity_config, &login_request).await;

        assert!(result.is_err(), "Expected error response");
        let error = result.unwrap_err();
        match error {
            LoginErrorApiResponse::OAuth2Error(oauth_error) => {
                assert!(matches!(
                    oauth_error,
                    crate::identity::api::response::OAuth2ErrorApiResponse::InvalidRequest { .. }
                ));
            }
            _ => panic!("Expected OAuth2Error variant"),
        }
    }

    #[tokio::test]
    async fn test_send_login_request_invalid_client() {
        let error_response = serde_json::json!({
            "error": "invalid_client",
            "error_description": "Client authentication failed"
        });

        let mock = Mock::given(matchers::method("POST"))
            .and(matchers::path("/identity/connect/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(error_response));

        let (mock_server, _) = start_api_mock(vec![mock]).await;
        let identity_config = create_identity_config(&mock_server);
        let login_request = create_test_login_request();

        let result = send_login_request(&identity_config, &login_request).await;

        assert!(result.is_err(), "Expected error response");
        let error = result.unwrap_err();
        match error {
            LoginErrorApiResponse::OAuth2Error(oauth_error) => {
                assert!(matches!(
                    oauth_error,
                    crate::identity::api::response::OAuth2ErrorApiResponse::InvalidClient { .. }
                ));
            }
            _ => panic!("Expected OAuth2Error variant"),
        }
    }

    // ==================== Error Propagation Tests ====================
    // These tests verify that errors from lower layers (reqwest, serde) are
    // properly propagated and converted to LoginErrorApiResponse.
    // Comprehensive error scenario testing is done in login_via_password_impl.rs
    // to verify end-to-end error handling through the full stack.

    #[tokio::test]
    async fn test_send_login_request_network_error() {
        let reqwest_client = reqwest::Client::new();
        let client = reqwest_middleware::ClientBuilder::new(reqwest_client).build();

        // Verify that network errors are propagated as UnexpectedError.
        // This test confirms the error conversion mechanism works.
        let identity_config = Configuration {
            base_path: "http://127.0.0.1:1/identity".to_string(), // Port 1 will refuse connections
            client,
            ..Default::default()
        };

        let login_request = create_test_login_request();
        let result = send_login_request(&identity_config, &login_request).await;

        assert!(result.is_err(), "Expected error due to network failure");
        match result.unwrap_err() {
            LoginErrorApiResponse::UnexpectedError(msg) => {
                assert!(!msg.is_empty(), "Error message should not be empty");
            }
            _ => panic!("Expected UnexpectedError for network failure"),
        }
    }

    // ==================== Response Parsing Tests ====================

    #[tokio::test]
    async fn test_send_login_request_incomplete_success_response() {
        // Verify that responses with missing required fields fail during
        // deserialization/validation. This tests a different code path than
        // JSON parsing errors - the JSON is valid but the data is incomplete.
        let incomplete_response = serde_json::json!({
            "access_token": "token_without_required_fields"
            // Missing expires_in, token_type, and other required fields
        });

        let mock = Mock::given(matchers::method("POST"))
            .and(matchers::path("/identity/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(incomplete_response));

        let (mock_server, _) = start_api_mock(vec![mock]).await;
        let identity_config = create_identity_config(&mock_server);
        let login_request = create_test_login_request();

        let result = send_login_request(&identity_config, &login_request).await;

        assert!(
            result.is_err(),
            "Expected error due to incomplete success response"
        );
        match result.unwrap_err() {
            LoginErrorApiResponse::UnexpectedError(msg) => {
                assert!(!msg.is_empty(), "Error message should not be empty");
            }
            _ => panic!("Expected UnexpectedError for incomplete response"),
        }
    }

    // ==================== Header Verification Tests ====================

    #[tokio::test]
    async fn test_send_login_request_verifies_headers() {
        let success_response = create_mock_success_response();
        let mock = add_standard_request_matchers(
            Mock::given(matchers::method("POST")).and(matchers::path("/identity/connect/token")),
        )
        // Verify all required headers including content-type
        .and(matchers::header(
            reqwest::header::CONTENT_TYPE.as_str(),
            "application/x-www-form-urlencoded",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(success_response));

        let (mock_server, _) = start_api_mock(vec![mock]).await;
        let identity_config = create_identity_config(&mock_server);
        let login_request = create_test_login_request();

        let result = send_login_request(&identity_config, &login_request).await;

        assert!(
            result.is_ok(),
            "Request should succeed with correct headers"
        );
    }
}
