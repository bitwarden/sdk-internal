use bitwarden_core::key_management::MasterPasswordAuthenticationData;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::identity::{
    LoginClient,
    api::{request::LoginApiRequest, send_login_request},
    login_via_password::{PasswordLoginApiRequest, PasswordLoginError, PasswordLoginRequest},
    models::LoginResponse,
};

#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl LoginClient {
    /// Authenticates a user via email and master password.
    ///
    /// Derives the master password hash using KDF settings from prelogin, then sends
    /// the authentication request to obtain access tokens and vault keys.
    ///
    /// # Errors
    ///
    /// - [`PasswordLoginError::InvalidUsernameOrPassword`] - Invalid credentials
    /// - [`PasswordLoginError::PasswordAuthenticationDataDerivation`] - KDF processing failed
    /// - [`PasswordLoginError::Unknown`] - Network error or unexpected server response
    ///
    /// # Example
    ///
    /// See the [`login_via_password`](crate::identity::login_via_password) module for
    /// complete usage examples and security details.
    pub async fn login_via_password(
        &self,
        request: PasswordLoginRequest,
    ) -> Result<LoginResponse, PasswordLoginError> {
        let master_password_authentication = MasterPasswordAuthenticationData::derive(
            &request.password,
            &request.prelogin_response.kdf,
            &request.email,
        )?;

        let api_request: LoginApiRequest<PasswordLoginApiRequest> =
            (request, master_password_authentication).into();

        let api_configs = self.client.internal.get_api_configurations().await;

        let response = send_login_request(&api_configs.identity_config, &api_request).await;

        response.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::{ClientSettings, DeviceType};
    use bitwarden_crypto::{
        Kdf, default_argon2_iterations, default_argon2_memory, default_argon2_parallelism,
        default_pbkdf2_iterations,
    };
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

    #[derive(Debug, Clone, Copy)]
    enum TestKdfType {
        Pbkdf2,
        Argon2id,
    }

    // Mock success response constants (using real-world valid encrypted data format)
    const TEST_ACCESS_TOKEN: &str = "test_access_token";
    const TEST_TOKEN_TYPE: &str = "Bearer";
    const TEST_EXPIRES_IN: u64 = 3600;
    const TEST_SCOPE: &str = "api offline_access";
    const TEST_REFRESH_TOKEN: &str = "test_refresh_token";
    const TEST_PRIVATE_KEY: &str = "2.SVgjObXyZZKLDVxM3y197w==|tUHZ+bo2o7Y9NyAPPqWOhhuaDiiYT26R2vPI0ILqg8W1vtjq+kzsGHPRZhA1nOXAcJ/ACe77YGFicueH+tryWZHgF1whGZxXza8JPYVtd4k8vO2NE7j8MUZ0FHHq7O+mUiVql0+mC1Af9gM5xp8W022aWgobyu4IZQi6l5hmJZ76NvzUbxDRFadzd8/sxFh+g3I4lEl5kQfzIi3IT0PmX3h75I/8jyGzgWxuUpLiko8hNkIwcjLXesCE641hH8oCtTtwzowZfuRUTO6O/WSR5fHMR2nR2IKf+YvK3SvlywvFTbOAzi7GLNd6NPOZ5ohJrJWtThUZ+65N3CFIczhjj/KvtR5NYVlXlCKWGRLjMsG5Aj8MPCAtAGH8AT6qRoDyh7jXF8SjMo/7BpFay9Xp+kd8M79LEFyUVMybShJ/1Es1qDNCZlnYP8iy1uQe1osLIzSk4IcH2uAD91jvWAOaJGw+HuAOjhqBlP2I7hI8jST5pJAeAzZeY1mnfryYB92wdDVPWKHp+nFcDl34w9lwQRAxken+yxCaepJCRyTXYzpzDNW7Si47PKndchSof9j27MBXTjoOgcsCN2s/V6mNomNybwfN/8J5ts8BNatTnCfiDhV/zrHP9N7wjRXjYoVTLTHXBJqehnLXCNFjnWWmbUTz0fMIRC5q4iNRnSmGMuuCGZfCvlhaIaSVbw35K7ksjTvakJQ8npZU+ULq0Z49jw10GULUbXrP0h/VG+ScKGsRG3E1AOYtd2ff2oe8ht03IpopQWKKk8vqofhDKG++E+SYd/VgMo2O9tuOKilrKCoOBW17/FIftCpWqdGmbG3OBnKiXNOeelqd51i0n9G2ddYhgt+a++8J3UfmrNTX5483+g2usJeJBkKfIbB87FaCxBRSBdvy+bPIPqm6dEWLhk5m3GGkPCndpZywef+tpV7NkC6J8cUDQS0ah1w7r9DG5kNdoSWHbvwhuPR8Ytk8uPdAHI2vOcO/4E6CCPGlsGbXq6egZ39XypO7QJ4+NWTzGDiNGSVOB4Mrxe23++GYRqaMS3bGX0cLKXvCuR1sjYYiM8kechXcmIBGKavs3JrZcT7qEJ8bEpnFQcV+F0iW1bvRTCclVM8XSTbeX6SktHs6fO3vrV+bfkVJsWUAbqR/2di0B9Ye97kJign/03oKUUpg8ksapMfr+IE4CVdHeEC4Xq/y5I+R5TRP/EXiIu2mDIgx7nITj0oTysl070t0OC8QLFrpUkZxjx7ELq76NjMc0IIgumWsivRyBeqz6r3lIA25b6H/3+9xrpjZFb/K/M/NMXFdenjflhYaQLzzsO9Cz7EAorYTf6bV0+g43GyUOC6w0D8R7rerfsVSnwIENlEwpd4s5TC+rWjNPG1r1w91E+It1UbuvBDBTMIZw4BRrCd5/2G0nQyNnNWxn5WLkg3xRCmPYqcVFygagJLh6baYGLb1SVmRu8NF2QMggRsYDkckql6gseq5gGGCfcaFLtAHgfdlfV4jnSZ0tuYpjsLRYhUD/oFGlM56sxnMe/EX6DdDnoGFlAxkRNeHuiY6tdlNhbOAyRjJwQL1Vnweip5vvrHpbEsR6z71E05dwEDnK+2Gz7gVq2x4BIzkLm3MwlOmZFsbLewHr6vB5mm+rgM=|YfKU1iB2Yn/pqeBDbE2IXnpVIlGUR0Sjv9twpnNklHU=";
    const TEST_PUBLIC_KEY: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqRwZGmKLN34tUq+lLT50JoXJaEJh2E13g8IMFYd5xaywJxA63rnQ5rDa6HFrjjyhg0kbhY60Igv7tpeR7Hq6VTU2CnsRmT47+3ZKm2Y8w/h8Dk0X/a8QcxMbvJZP+2wQ0/6lIbfxRYm7cCi8KZz03mz79lUBJxioy8N+46rMwlj9HQCb8tle5gyEYtF+XtWeAP3JpVvRs3unNvlgThCETnusAIruIJzNX8e+0z7HkzNyFQ3/jY+MyZZUTz3X+r3werc8r94W/4EgoLdjg4651KBQbJuMiknlRzpN+gipClDyjgILxiswtGjuCr80Dyk+jhpDmYhytRcpinnjqkLlzwIDAQAB";
    const TEST_ENCRYPTED_USER_KEY: &str = "2.EvwbalCwa3ba6j/eEtGOLA==|Nd+7WgEZpd3fsGmpDHOknPhS9e8SVeXpmeJQDTLI3Ki9S7BB/L+k0TxzRnUtcMx646d4Nfco5mz7Q1mMrGO/PGtf4FNleyCR9LMIzHneiRI=|B9bEzJ4LLh0Vz2zexhBwZBQSmXWsPdRKL+haJG/KB6c=";
    const TEST_KDF_TYPE: i32 = 0;
    const TEST_KDF_ITERATIONS: i32 = 600000;
    const TEST_PUSH_TOKEN: &str = "test_push_token";

    fn make_identity_client(mock_server: &wiremock::MockServer) -> LoginClient {
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

    fn make_password_login_request(kdf_type: TestKdfType) -> PasswordLoginRequest {
        let kdf = match kdf_type {
            TestKdfType::Pbkdf2 => Kdf::PBKDF2 {
                iterations: default_pbkdf2_iterations(),
            },
            TestKdfType::Argon2id => Kdf::Argon2id {
                iterations: default_argon2_iterations(),
                memory: default_argon2_memory(),
                parallelism: default_argon2_parallelism(),
            },
        };

        PasswordLoginRequest {
            login_request: LoginRequest {
                client_id: TEST_CLIENT_ID.to_string(),
                device: LoginDeviceRequest {
                    device_type: DeviceType::SDK,
                    device_identifier: TEST_DEVICE_IDENTIFIER.to_string(),
                    device_name: TEST_DEVICE_NAME.to_string(),
                    device_push_token: Some(TEST_PUSH_TOKEN.to_string()),
                },
            },
            email: TEST_EMAIL.to_string(),
            password: TEST_PASSWORD.to_string(),
            prelogin_response: PasswordPreloginResponse {
                kdf,
                salt: TEST_SALT.to_string(),
            },
        }
    }

    fn add_standard_login_headers(mock_builder: wiremock::MockBuilder) -> wiremock::MockBuilder {
        mock_builder
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
            .and(matchers::header(
                reqwest::header::PRAGMA.as_str(),
                "no-cache",
            ))
    }

    fn make_mock_success_response() -> serde_json::Value {
        serde_json::json!({
            "access_token": TEST_ACCESS_TOKEN,
            "expires_in": TEST_EXPIRES_IN,
            "token_type": TEST_TOKEN_TYPE,
            "refresh_token": TEST_REFRESH_TOKEN,
            "scope": TEST_SCOPE,
            "PrivateKey": TEST_PRIVATE_KEY,
            "AccountKeys": {
                "publicKeyEncryptionKeyPair": {
                    "wrappedPrivateKey": TEST_PRIVATE_KEY,
                    "publicKey": TEST_PUBLIC_KEY,
                    "Object": "publicKeyEncryptionKeyPair"
                },
                "Object": "privateKeys"
            },
            "Key": TEST_ENCRYPTED_USER_KEY,
            "MasterPasswordPolicy": {
                "Object": "masterPasswordPolicy"
            },
            "ForcePasswordReset": false,
            "Kdf": TEST_KDF_TYPE,
            "KdfIterations": TEST_KDF_ITERATIONS,
            "KdfMemory": null,
            "KdfParallelism": null,
            "UserDecryptionOptions": {
                "HasMasterPassword": true,
                "MasterPasswordUnlock": {
                    "Kdf": {
                        "KdfType": TEST_KDF_TYPE,
                        "Iterations": TEST_KDF_ITERATIONS
                    },
                    "MasterKeyEncryptedUserKey": TEST_ENCRYPTED_USER_KEY,
                    "Salt": TEST_EMAIL
                },
                "Object": "userDecryptionOptions"
            }
        })
    }

    fn assert_login_success_response(login_response: &LoginResponse) {
        match login_response {
            LoginResponse::Authenticated(success_response) => {
                assert_eq!(success_response.access_token, TEST_ACCESS_TOKEN);
                assert_eq!(success_response.token_type, TEST_TOKEN_TYPE);
                assert_eq!(success_response.expires_in, TEST_EXPIRES_IN);
                assert_eq!(success_response.scope, TEST_SCOPE);
                assert_eq!(
                    success_response.refresh_token,
                    Some(TEST_REFRESH_TOKEN.to_string())
                );
                assert_eq!(
                    success_response.user_key_wrapped_user_private_key,
                    Some(TEST_PRIVATE_KEY.to_string())
                );
                assert_eq!(success_response.two_factor_token, None);
                assert_eq!(success_response.force_password_reset, Some(false));
                assert_eq!(success_response.api_use_key_connector, None);

                // Verify user decryption options
                let decryption_options = &success_response.user_decryption_options;
                assert!(decryption_options.master_password_unlock.is_some());
                let mp_unlock = decryption_options.master_password_unlock.as_ref().unwrap();
                assert_eq!(
                    mp_unlock.master_key_wrapped_user_key.to_string(),
                    TEST_ENCRYPTED_USER_KEY
                );
                assert_eq!(mp_unlock.salt, TEST_EMAIL);

                // Verify master password policy is present
                assert!(success_response.master_password_policy.is_some());
            }
        }
    }

    #[tokio::test]
    async fn test_login_via_password_success() {
        let kdf_types = [TestKdfType::Pbkdf2, TestKdfType::Argon2id];

        for kdf_type in kdf_types {
            let raw_success = make_mock_success_response();

            let mock = add_standard_login_headers(
                Mock::given(matchers::method("POST")).and(matchers::path("identity/connect/token")),
            )
            .respond_with(ResponseTemplate::new(200).set_body_json(raw_success));

            let (mock_server, _api_config) = start_api_mock(vec![mock]).await;
            let identity_client = make_identity_client(&mock_server);

            let request = make_password_login_request(kdf_type);
            let result = identity_client.login_via_password(request).await;

            assert!(result.is_ok(), "Failed for KDF type: {:?}", kdf_type);
            let login_response = result.unwrap();
            assert_login_success_response(&login_response);
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

        let request = make_password_login_request(TestKdfType::Pbkdf2);
        let result = identity_client.login_via_password(request).await;

        assert!(result.is_err());
        let error = result.unwrap_err();

        assert!(matches!(
            error,
            PasswordLoginError::InvalidUsernameOrPassword
        ));
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

        let request = make_password_login_request(TestKdfType::Pbkdf2);
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

        let request = make_password_login_request(TestKdfType::Pbkdf2);
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

        let request = make_password_login_request(TestKdfType::Pbkdf2);
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

    #[tokio::test]
    async fn test_login_via_password_invalid_kdf_configuration() {
        // No mock server needed - error occurs during KDF derivation before API call
        let (mock_server, _api_config) = start_api_mock(vec![]).await;
        let identity_client = make_identity_client(&mock_server);

        // Create a request with PBKDF2 iterations below the minimum (5000)
        // This will cause derive() to fail with InsufficientKdfParameters
        let request = PasswordLoginRequest {
            login_request: LoginRequest {
                client_id: TEST_CLIENT_ID.to_string(),
                device: LoginDeviceRequest {
                    device_type: DeviceType::SDK,
                    device_identifier: TEST_DEVICE_IDENTIFIER.to_string(),
                    device_name: TEST_DEVICE_NAME.to_string(),
                    device_push_token: Some(TEST_PUSH_TOKEN.to_string()),
                },
            },
            email: TEST_EMAIL.to_string(),
            password: TEST_PASSWORD.to_string(),
            prelogin_response: PasswordPreloginResponse {
                kdf: Kdf::PBKDF2 {
                    iterations: std::num::NonZeroU32::new(100).unwrap(), // Below minimum of 5000
                },
                salt: TEST_SALT.to_string(),
            },
        };

        let result = identity_client.login_via_password(request).await;

        assert!(result.is_err());
        let error = result.unwrap_err();

        // Verify it's the PasswordAuthenticationDataDerivation error variant
        assert!(
            matches!(
                error,
                PasswordLoginError::PasswordAuthenticationDataDerivation(_)
            ),
            "Expected PasswordAuthenticationDataDerivation error, got: {:?}",
            error
        );
    }
}
