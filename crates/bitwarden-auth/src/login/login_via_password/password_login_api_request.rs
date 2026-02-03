use bitwarden_core::key_management::MasterPasswordAuthenticationData;
use serde::{Deserialize, Serialize};

use crate::{
    api::enums::GrantType,
    login::{api::request::LoginApiRequest, login_via_password::PasswordLoginRequest},
};

/// Internal API request model for logging in via password.
///
/// This struct represents the password-specific fields sent to the Identity API's
/// `/connect/token` endpoint. It is combined with common login fields in [`LoginApiRequest`].
///
/// # Field Mappings
///
/// The API expects OAuth2-style field names, so we rename our fields during serialization:
/// - `email` → `"username"` - The user's email address (OAuth2 uses "username")
/// - `master_password_hash` → `"password"` - The derived master password hash (not the raw
///   password)
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PasswordLoginApiRequest {
    /// Bitwarden user email address.
    ///
    /// Serialized as `"username"` to match OAuth2 conventions expected by the Identity API.
    #[serde(rename = "username")]
    pub email: String,

    /// Derived master password server authentication hash.
    /// Serialized as `"password"` to match OAuth2 conventions expected by the Identity API.
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
    use bitwarden_crypto::Kdf;

    use super::*;
    use crate::login::{
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
                kdf: Kdf::default_pbkdf2(),
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

    #[test]
    fn test_password_login_api_request_serialization() {
        use crate::{api::enums::scopes_to_string, login::api::request::STANDARD_USER_SCOPES};

        // Create a complete API request with all fields
        let request = make_test_password_login_request(true);
        let master_password_auth = make_test_master_password_auth();

        let api_request: LoginApiRequest<PasswordLoginApiRequest> =
            (request, master_password_auth).into();

        // Serialize to URL-encoded form data (as used by the API)
        let serialized =
            serde_urlencoded::to_string(&api_request).expect("Failed to serialize LoginApiRequest");

        // Verify OAuth2 standard fields use snake_case
        // Serialize GrantType::Password to get the actual string value
        let expected_grant_type =
            serde_urlencoded::to_string([("grant_type", &GrantType::Password)])
                .expect("Failed to serialize GrantType");
        assert!(
            serialized.contains(&expected_grant_type),
            "Should contain {expected_grant_type}, got: {serialized}",
        );
        assert!(
            serialized.contains(&format!("client_id={TEST_CLIENT_ID}")),
            "Should contain client_id, got: {serialized}",
        );
        // Verify scope matches the standard scopes (space becomes + in URL encoding)
        let expected_scope = scopes_to_string(STANDARD_USER_SCOPES).replace(' ', "+");
        assert!(
            serialized.contains(&format!("scope={expected_scope}")),
            "Should contain scope={expected_scope}, got: {serialized}",
        );

        // Verify password-specific fields use snake_case (OAuth2 convention)
        // Email is URL-encoded (@ becomes %40)
        let url_encoded_email = TEST_EMAIL.replace('@', "%40");
        assert!(
            serialized.contains(&format!("username={url_encoded_email}")),
            "Email should be serialized as 'username' per OAuth2 convention, got: {serialized}",
        );
        assert!(
            serialized.contains("password="),
            "Should contain password field with hash, got: {serialized}",
        );
        // Verify the actual hash is present (check for the hash in the serialized output)
        // The hash may be URL-encoded, so we just verify the field exists with content
        let password_field_present = serialized
            .split('&')
            .any(|pair| pair.starts_with("password=") && pair.len() > "password=".len());
        assert!(
            password_field_present,
            "Should contain password field with hash value, got: {serialized}",
        );

        // Verify Bitwarden custom fields use camelCase
        // DeviceType serializes using Debug format (variant name)
        let expected_device_type = format!("deviceType={:?}", DeviceType::SDK);
        assert!(
            serialized.contains(&expected_device_type),
            "Should contain {expected_device_type}, got: {serialized}",
        );
        assert!(
            serialized.contains(&format!("deviceIdentifier={TEST_DEVICE_IDENTIFIER}")),
            "Should contain deviceIdentifier field, got: {serialized}",
        );
        // Device name is URL-encoded (space becomes +)
        let url_encoded_device_name = TEST_DEVICE_NAME.replace(' ', "+");
        assert!(
            serialized.contains(&format!("deviceName={url_encoded_device_name}")),
            "Should contain deviceName={url_encoded_device_name}, got: {serialized}",
        );
        assert!(
            serialized.contains(&format!("devicePushToken={TEST_DEVICE_PUSH_TOKEN}")),
            "Should contain devicePushToken field, got: {serialized}",
        );

        // Verify optional fields are not present when None
        assert!(
            !serialized.contains("twoFactorToken"),
            "Should not contain twoFactorToken when None, got: {serialized}",
        );
        assert!(
            !serialized.contains("twoFactorProvider"),
            "Should not contain twoFactorProvider when None, got: {serialized}",
        );
        assert!(
            !serialized.contains("twoFactorRemember"),
            "Should not contain twoFactorRemember when None, got: {serialized}",
        );
    }
}
