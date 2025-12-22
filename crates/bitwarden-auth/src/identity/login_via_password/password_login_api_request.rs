use bitwarden_core::key_management::MasterPasswordAuthenticationData;
use serde::{Deserialize, Serialize};

use crate::{
    api::enums::GrantType,
    identity::{api::request::LoginApiRequest, login_via_password::PasswordLoginRequest},
};

/// Internal API request model for logging in via password.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PasswordLoginApiRequest {
    /// Bitwarden user email address
    #[serde(rename = "username")]
    pub email: String,

    /// Bitwarden user master password hash
    #[serde(rename = "password")]
    pub master_password_hash: String,
}

/// Converts a `PasswordLoginRequest` and `MasterPasswordAuthenticationData` into a
/// `PasswordLoginApiRequest` for making the API call.
impl From<(PasswordLoginRequest, MasterPasswordAuthenticationData)>
    for LoginApiRequest<PasswordLoginApiRequest>
{
    fn from(
        (request, master_password_authentication): (
            PasswordLoginRequest,
            MasterPasswordAuthenticationData,
        ),
    ) -> Self {
        // Create the PasswordLoginApiRequest with required fields
        let password_login_api_request = PasswordLoginApiRequest {
            email: request.email,
            master_password_hash: master_password_authentication
                .master_password_authentication_hash
                .to_string(),
        };

        // Create the UserLoginApiRequest with standard scopes configuration and return
        LoginApiRequest::new(
            request.login_request.client_id,
            GrantType::Password,
            request.login_request.device.device_type,
            request.login_request.device.device_identifier,
            request.login_request.device.device_name,
            request.login_request.device.device_push_token,
            password_login_api_request,
        )
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::DeviceType;
    use bitwarden_crypto::{Kdf, default_pbkdf2_iterations};

    use super::*;
    use crate::identity::{
        login_via_password::PasswordPreloginResponse,
        models::{LoginDeviceRequest, LoginRequest},
    };

    const TEST_EMAIL: &str = "test@example.com";
    const TEST_PASSWORD: &str = "test-password-123";
    const TEST_SALT: &str = "test-salt-value";
    const TEST_CLIENT_ID: &str = "connector";
    const TEST_DEVICE_IDENTIFIER: &str = "test-device-id";
    const TEST_DEVICE_NAME: &str = "Test Device";
    const TEST_DEVICE_PUSH_TOKEN: &str = "test-push-token";

    fn make_test_password_login_request(with_push_token: bool) -> PasswordLoginRequest {
        PasswordLoginRequest {
            login_request: LoginRequest {
                client_id: TEST_CLIENT_ID.to_string(),
                device: LoginDeviceRequest {
                    device_type: DeviceType::SDK,
                    device_identifier: TEST_DEVICE_IDENTIFIER.to_string(),
                    device_name: TEST_DEVICE_NAME.to_string(),
                    device_push_token: if with_push_token {
                        Some(TEST_DEVICE_PUSH_TOKEN.to_string())
                    } else {
                        None
                    },
                },
            },
            email: TEST_EMAIL.to_string(),
            password: TEST_PASSWORD.to_string(),
            prelogin_response: PasswordPreloginResponse {
                kdf: Kdf::PBKDF2 {
                    iterations: default_pbkdf2_iterations(),
                },
                salt: TEST_SALT.to_string(),
            },
        }
    }

    fn make_test_master_password_auth() -> MasterPasswordAuthenticationData {
        let request = make_test_password_login_request(false);
        MasterPasswordAuthenticationData::derive(
            &request.password,
            &request.prelogin_response.kdf,
            &request.email,
        )
        .unwrap()
    }

    #[test]
    fn test_password_login_request_conversion() {
        let request = make_test_password_login_request(true);
        let master_password_auth = make_test_master_password_auth();
        let expected_hash = master_password_auth
            .master_password_authentication_hash
            .to_string();

        let api_request: LoginApiRequest<PasswordLoginApiRequest> =
            (request, master_password_auth).into();

        // Verify grant type is set to password
        assert_eq!(api_request.grant_type, GrantType::Password);

        // Verify standard scopes
        assert_eq!(api_request.scope, "api offline_access");

        // Verify common fields
        assert_eq!(api_request.client_id, TEST_CLIENT_ID);
        assert_eq!(api_request.device_type, DeviceType::SDK);
        assert_eq!(api_request.device_identifier, TEST_DEVICE_IDENTIFIER);
        assert_eq!(api_request.device_name, TEST_DEVICE_NAME);
        assert_eq!(
            api_request.device_push_token,
            Some(TEST_DEVICE_PUSH_TOKEN.to_string())
        );

        // Verify password-specific fields
        assert_eq!(api_request.login_mechanism_fields.email, TEST_EMAIL);
        assert_eq!(
            api_request.login_mechanism_fields.master_password_hash,
            expected_hash
        );
        assert!(
            !api_request
                .login_mechanism_fields
                .master_password_hash
                .is_empty()
        );
    }
}
