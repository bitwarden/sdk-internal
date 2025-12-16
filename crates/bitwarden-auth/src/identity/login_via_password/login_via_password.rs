use bitwarden_core::key_management::MasterPasswordAuthenticationData;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::identity::{
    LoginClient,
    api::{request::LoginApiRequest, send_login_request},
    login_via_password::{PasswordLoginApiRequest, PasswordLoginError, PasswordLoginRequest},
    models::LoginResponse,
};

#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl LoginClient {
    /// Logs in a user via their email and master password.
    ///
    /// This function derives the necessary master password authentication data
    /// using the provided prelogin data, constructs the appropriate API request,
    /// and sends the request to the Identity connect/token endpoint to log the user in.
    pub async fn login_via_password(
        &self,
        request: PasswordLoginRequest,
    ) -> Result<LoginResponse, PasswordLoginError> {
        // use request password prelogin data to derive master password authentication data:
        let master_password_authentication: Result<
            MasterPasswordAuthenticationData,
            bitwarden_core::key_management::MasterPasswordError,
        > = MasterPasswordAuthenticationData::derive(
            &request.password,
            &request.prelogin_response.kdf,
            &request.email,
        );

        // construct API request
        let api_request: LoginApiRequest<PasswordLoginApiRequest> =
            (request, master_password_authentication.unwrap()).into();

        // make API call to login endpoint with api_request
        let response = send_login_request(&self.identity_config, &api_request).await;

        response.map_err(Into::into)
    }
}

// TODO: these tests will have to be updated once send_login_request settles
#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use bitwarden_core::{ClientSettings, DeviceType};
    use bitwarden_crypto::Kdf;
    use bitwarden_test::start_api_mock;
    use wiremock::{Mock, ResponseTemplate, matchers};

    use super::*;
    use crate::identity::{
        login_via_password::{PasswordLoginRequest, PasswordPreloginResponse},
        models::{LoginDeviceRequest, LoginRequest, LoginResponse},
    };

    const TEST_EMAIL: &str = "test@example.com";
    const TEST_PASSWORD: &str = "test-password-123";
    const TEST_SALT: &str = "test-salt-value";
    const TEST_CLIENT_ID: &str = "connector";
    const TEST_DEVICE_IDENTIFIER: &str = "test-device-id";
    const TEST_DEVICE_NAME: &str = "Test Device";
    const PBKDF2_ITERATIONS: u32 = 600000;

    fn make_identity_client(mock_server: &wiremock::MockServer) -> LoginClient {
        let settings = ClientSettings {
            identity_url: format!("http://{}/identity", mock_server.address()),
            api_url: format!("http://{}/api", mock_server.address()),
            user_agent: "Bitwarden Rust-SDK [TEST]".into(),
            device_type: DeviceType::SDK,
            bitwarden_client_version: None,
        };
        LoginClient::new(settings)
    }

    fn make_password_login_request() -> PasswordLoginRequest {
        PasswordLoginRequest {
            login_request: LoginRequest {
                client_id: TEST_CLIENT_ID.to_string(),
                device: LoginDeviceRequest {
                    device_type: DeviceType::SDK,
                    device_identifier: TEST_DEVICE_IDENTIFIER.to_string(),
                    device_name: TEST_DEVICE_NAME.to_string(),
                    device_push_token: None,
                },
            },
            email: TEST_EMAIL.to_string(),
            password: TEST_PASSWORD.to_string(),
            prelogin_response: PasswordPreloginResponse {
                kdf: Kdf::PBKDF2 {
                    iterations: NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
                },
                salt: TEST_SALT.to_string(),
            },
        }
    }

    fn make_mock_success_response() -> serde_json::Value {
        serde_json::json!({
            "access_token": "test_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "api offline_access",
            "refresh_token": "test_refresh_token",
            "UserDecryptionOptions": {
                "HasMasterPassword": true,
                "Object": "userDecryptionOptions"
            }
        })
    }

    #[tokio::test]
    async fn test_login_via_password_success() {
        let raw_success = make_mock_success_response();

        let mock = Mock::given(matchers::method("POST"))
            .and(matchers::path("identity/connect/token"))
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
            .respond_with(ResponseTemplate::new(200).set_body_json(raw_success));

        let (mock_server, _api_config) = start_api_mock(vec![mock]).await;
        let identity_client = make_identity_client(&mock_server);

        let request = make_password_login_request();
        let result = identity_client.login_via_password(request).await;

        assert!(result.is_ok());
        let login_response = result.unwrap();

        match login_response {
            LoginResponse::Authenticated(success_response) => {
                assert_eq!(success_response.access_token, "test_access_token");
                assert_eq!(success_response.token_type, "Bearer");
                assert_eq!(success_response.expires_in, 3600);
                assert_eq!(success_response.scope, "api offline_access");
                assert_eq!(
                    success_response.refresh_token,
                    Some("test_refresh_token".to_string())
                );
            }
        }
    }

    #[tokio::test]
    async fn test_login_via_password_invalid_credentials() {
        let error_response = serde_json::json!({
            "error": "invalid_grant",
            "error_description": "invalid_username_or_password"
        });

        let mock = Mock::given(matchers::method("POST"))
            .and(matchers::path("identity/connect/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(error_response));

        let (mock_server, _api_config) = start_api_mock(vec![mock]).await;
        let identity_client = make_identity_client(&mock_server);

        let request = make_password_login_request();
        let result = identity_client.login_via_password(request).await;

        assert!(result.is_err());
        let error = result.unwrap_err();

        assert!(matches!(
            error,
            PasswordLoginError::InvalidUsernameOrPassword
        ));
    }

    #[tokio::test]
    async fn test_login_via_password_with_argon2id_kdf() {
        let raw_success = make_mock_success_response();

        let mock = Mock::given(matchers::method("POST"))
            .and(matchers::path("identity/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(raw_success));

        let (mock_server, _api_config) = start_api_mock(vec![mock]).await;
        let identity_client = make_identity_client(&mock_server);

        let mut request = make_password_login_request();
        request.prelogin_response.kdf = Kdf::Argon2id {
            iterations: NonZeroU32::new(3).unwrap(),
            memory: NonZeroU32::new(64).unwrap(),
            parallelism: NonZeroU32::new(4).unwrap(),
        };

        let result = identity_client.login_via_password(request).await;

        assert!(result.is_ok());
        let login_response = result.unwrap();

        match login_response {
            LoginResponse::Authenticated(success_response) => {
                assert_eq!(success_response.access_token, "test_access_token");
            }
        }
    }

    #[tokio::test]
    async fn test_login_via_password_invalid_request() {
        let error_response = serde_json::json!({
            "error": "invalid_request",
            "error_description": "Missing required parameter"
        });

        let mock = Mock::given(matchers::method("POST"))
            .and(matchers::path("identity/connect/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(error_response));

        let (mock_server, _api_config) = start_api_mock(vec![mock]).await;
        let identity_client = make_identity_client(&mock_server);

        let request = make_password_login_request();
        let result = identity_client.login_via_password(request).await;

        assert!(result.is_err());
        let error = result.unwrap_err();

        match error {
            PasswordLoginError::Unknown(msg) => {
                assert!(msg.contains("Invalid request"));
                assert!(msg.contains("Missing required parameter"));
            }
            _ => panic!("Expected Unknown error variant"),
        }
    }

    #[tokio::test]
    async fn test_login_via_password_invalid_client() {
        let error_response = serde_json::json!({
            "error": "invalid_client",
            "error_description": "Client authentication failed"
        });

        let mock = Mock::given(matchers::method("POST"))
            .and(matchers::path("identity/connect/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(error_response));

        let (mock_server, _api_config) = start_api_mock(vec![mock]).await;
        let identity_client = make_identity_client(&mock_server);

        let request = make_password_login_request();
        let result = identity_client.login_via_password(request).await;

        assert!(result.is_err());
        let error = result.unwrap_err();

        match error {
            PasswordLoginError::Unknown(msg) => {
                assert!(msg.contains("Invalid client"));
                assert!(msg.contains("Client authentication failed"));
            }
            _ => panic!("Expected Unknown error variant"),
        }
    }

    #[tokio::test]
    async fn test_login_via_password_unexpected_error() {
        let error_response = serde_json::json!({
            "unexpected_field": "unexpected_value"
        });

        let mock = Mock::given(matchers::method("POST"))
            .and(matchers::path("identity/connect/token"))
            .respond_with(ResponseTemplate::new(500).set_body_json(error_response));

        let (mock_server, _api_config) = start_api_mock(vec![mock]).await;
        let identity_client = make_identity_client(&mock_server);

        let request = make_password_login_request();
        let result = identity_client.login_via_password(request).await;

        assert!(result.is_err());
        let error = result.unwrap_err();

        match error {
            PasswordLoginError::Unknown(msg) => {
                assert!(msg.contains("Unexpected error"));
            }
            _ => panic!("Expected Unknown error variant"),
        }
    }

    // TODO: figure out why this is a test?
    #[tokio::test]
    async fn test_login_via_password_with_device_push_token() {
        let raw_success = make_mock_success_response();

        let mock = Mock::given(matchers::method("POST"))
            .and(matchers::path("identity/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(raw_success));

        let (mock_server, _api_config) = start_api_mock(vec![mock]).await;
        let identity_client = make_identity_client(&mock_server);

        let mut request = make_password_login_request();
        request.login_request.device.device_push_token = Some("test_push_token".to_string());

        let result = identity_client.login_via_password(request).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_login_via_password_with_different_device_types() {
        let device_types = [
            DeviceType::Android,
            DeviceType::iOS,
            DeviceType::ChromeExtension,
            DeviceType::FirefoxExtension,
            DeviceType::OperaExtension,
            DeviceType::EdgeExtension,
            DeviceType::WindowsDesktop,
            DeviceType::MacOsDesktop,
            DeviceType::LinuxDesktop,
            DeviceType::ChromeBrowser,
            DeviceType::FirefoxBrowser,
            DeviceType::OperaBrowser,
            DeviceType::EdgeBrowser,
            DeviceType::IEBrowser,
            DeviceType::UnknownBrowser,
            DeviceType::AndroidAmazon,
            DeviceType::UWP,
            DeviceType::SafariBrowser,
            DeviceType::VivaldiBrowser,
            DeviceType::VivaldiExtension,
            DeviceType::SafariExtension,
            DeviceType::SDK,
        ];

        for device_type in device_types {
            let raw_success = make_mock_success_response();

            let mock = Mock::given(matchers::method("POST"))
                .and(matchers::path("identity/connect/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(raw_success));

            let (mock_server, _api_config) = start_api_mock(vec![mock]).await;
            let identity_client = make_identity_client(&mock_server);

            let mut request = make_password_login_request();
            request.login_request.device.device_type = device_type;

            let result = identity_client.login_via_password(request).await;

            assert!(result.is_ok(), "Failed for device type: {:?}", device_type);
        }
    }

    #[tokio::test]
    async fn test_login_via_password_verifies_request_body_contents() {
        let raw_success = make_mock_success_response();

        let mock = Mock::given(matchers::method("POST"))
            .and(matchers::path("identity/connect/token"))
            .and(matchers::body_string_contains("grant_type"))
            .and(matchers::body_string_contains("password"))
            .and(matchers::body_string_contains("username"))
            .and(matchers::body_string_contains("client_id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(raw_success));

        let (mock_server, _api_config) = start_api_mock(vec![mock]).await;
        let identity_client = make_identity_client(&mock_server);

        let request = make_password_login_request();
        let result = identity_client.login_via_password(request).await;

        assert!(result.is_ok());
    }
}
