use bitwarden_api_identity::models::PasswordPreloginRequestModel;
use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::login::{LoginClient, login_via_password::PasswordPreloginResponse};

/// Error type for password prelogin operations
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum PasswordPreloginError {
    /// API error occurred during the prelogin request
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A required field was missing in the response
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl LoginClient {
    /// Retrieves the data required before authenticating with a password.
    /// This includes the user's KDF configuration needed to properly derive the master key.
    pub async fn get_password_prelogin(
        &self,
        email: String,
    ) -> Result<PasswordPreloginResponse, PasswordPreloginError> {
        let request_model = PasswordPreloginRequestModel::new(email);
        let api_configs = self.client.internal.get_api_configurations().await;
        let response = api_configs
            .identity_client
            .accounts_api()
            .post_password_prelogin(Some(request_model))
            .await
            .map_err(ApiError::from)?;

        Ok(PasswordPreloginResponse::try_from(response)?)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use bitwarden_api_identity::models::KdfType;
    use bitwarden_core::{ClientSettings, DeviceType};
    use bitwarden_crypto::Kdf;
    use bitwarden_test::start_api_mock;
    use wiremock::{Mock, ResponseTemplate, matchers};

    use super::*;

    const TEST_EMAIL: &str = "test@example.com";
    const TEST_SALT_PBKDF2: &str = "test-salt-value";
    const TEST_SALT_ARGON2: &str = "argon2-salt-value";

    fn make_login_client(mock_server: &wiremock::MockServer) -> LoginClient {
        let settings = ClientSettings {
            identity_url: format!("http://{}/identity", mock_server.address()),
            api_url: format!("http://{}/api", mock_server.address()),
            user_agent: "Bitwarden Rust-SDK [TEST]".into(),
            device_type: DeviceType::SDK,
            device_identifier: None,
            bitwarden_client_version: None,
            bitwarden_package_type: None,
        };
        LoginClient::new(settings)
    }

    fn mock_default_pbkdf2_iterations() -> NonZeroU32 {
        let Kdf::PBKDF2 { iterations } = Kdf::default_pbkdf2() else {
            panic!("Expected PBKDF2 KDF");
        };
        iterations
    }

    fn mock_default_argon2_params() -> (NonZeroU32, NonZeroU32, NonZeroU32) {
        let Kdf::Argon2id {
            iterations,
            memory,
            parallelism,
        } = Kdf::default_argon2()
        else {
            panic!("Expected Argon2 KDF");
        };
        (iterations, memory, parallelism)
    }

    #[tokio::test]
    async fn test_get_password_prelogin_pbkdf2_success() {
        // Create a mock success response with PBKDF2
        let raw_success = serde_json::json!({
            "kdfSettings": {
                "kdfType": KdfType::PBKDF2_SHA256 as i32,
                "iterations": mock_default_pbkdf2_iterations().get()
            },
            "salt": TEST_SALT_PBKDF2
        });

        let mock = Mock::given(matchers::method("POST"))
            .and(matchers::path("identity/accounts/prelogin/password"))
            .and(matchers::header(
                reqwest::header::CONTENT_TYPE.as_str(),
                "application/json",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(raw_success));

        let (mock_server, _api_config) = start_api_mock(vec![mock]).await;
        let identity_client = make_login_client(&mock_server);

        let result = identity_client
            .get_password_prelogin(TEST_EMAIL.to_string())
            .await
            .unwrap();

        assert_eq!(result.salt, TEST_SALT_PBKDF2);
        match result.kdf {
            Kdf::PBKDF2 { iterations } => {
                assert_eq!(iterations, mock_default_pbkdf2_iterations());
            }
            _ => panic!("Expected PBKDF2 KDF type"),
        }
    }

    #[tokio::test]
    async fn test_get_password_prelogin_argon2id_success() {
        let (default_iterations, default_memory, default_parallelism) =
            mock_default_argon2_params();

        // Create a mock success response with Argon2id
        let raw_success = serde_json::json!({
            "kdfSettings": {
                "kdfType": KdfType::Argon2id as i32,
                "iterations": default_iterations.get(),
                "memory": default_memory.get(),
                "parallelism": default_parallelism.get(),
            },
            "salt": TEST_SALT_ARGON2
        });

        let mock = Mock::given(matchers::method("POST"))
            .and(matchers::path("identity/accounts/prelogin/password"))
            .and(matchers::header(
                reqwest::header::CONTENT_TYPE.as_str(),
                "application/json",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(raw_success));

        let (mock_server, _api_config) = start_api_mock(vec![mock]).await;
        let identity_client = make_login_client(&mock_server);

        let result = identity_client
            .get_password_prelogin(TEST_EMAIL.to_string())
            .await
            .unwrap();

        assert_eq!(result.salt, TEST_SALT_ARGON2);
        match result.kdf {
            Kdf::Argon2id {
                iterations,
                memory,
                parallelism,
            } => {
                assert_eq!(iterations, default_iterations);
                assert_eq!(memory, default_memory);
                assert_eq!(parallelism, default_parallelism);
            }
            _ => panic!("Expected Argon2id KDF type"),
        }
    }

    #[tokio::test]
    async fn test_get_password_prelogin_missing_kdf_settings() {
        // Create a mock response missing kdf_settings
        let raw_response = serde_json::json!({
            "salt": TEST_SALT_PBKDF2
        });

        let mock = Mock::given(matchers::method("POST"))
            .and(matchers::path("identity/accounts/prelogin/password"))
            .respond_with(ResponseTemplate::new(200).set_body_json(raw_response));

        let (mock_server, _api_config) = start_api_mock(vec![mock]).await;
        let identity_client = make_login_client(&mock_server);

        let result = identity_client
            .get_password_prelogin(TEST_EMAIL.to_string())
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PasswordPreloginError::MissingField(err) => {
                assert_eq!(err.0, "response.kdf_settings");
            }
            other => panic!("Expected MissingField error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_get_password_prelogin_missing_salt() {
        // Create a mock response missing salt
        let raw_response = serde_json::json!({
            "kdfSettings": {
                "kdfType": KdfType::PBKDF2_SHA256 as i32,
                "iterations": mock_default_pbkdf2_iterations().get(),
            }
        });

        let mock = Mock::given(matchers::method("POST"))
            .and(matchers::path("/identity/accounts/prelogin/password"))
            .respond_with(ResponseTemplate::new(200).set_body_json(raw_response));

        let (mock_server, _api_config) = start_api_mock(vec![mock]).await;
        let identity_client = make_login_client(&mock_server);

        let result = identity_client
            .get_password_prelogin(TEST_EMAIL.to_string())
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PasswordPreloginError::MissingField(err) => {
                assert_eq!(err.0, "response.salt");
            }
            other => panic!("Expected MissingField error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_get_password_prelogin_api_error() {
        // Create a mock 500 error
        let mock = Mock::given(matchers::method("POST"))
            .and(matchers::path("/identity/accounts/prelogin/password"))
            .respond_with(ResponseTemplate::new(500));

        let (mock_server, _api_config) = start_api_mock(vec![mock]).await;
        let identity_client = make_login_client(&mock_server);

        let result = identity_client
            .get_password_prelogin(TEST_EMAIL.to_string())
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PasswordPreloginError::Api(bitwarden_core::ApiError::ResponseContent {
                status,
                message: _,
            }) => {
                assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
            }
            other => panic!("Expected Api ResponseContent error, got {:?}", other),
        }
    }
}
