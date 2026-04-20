use std::fmt::Debug;

use bitwarden_core::DeviceType;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::api::enums::{GrantType, Scope, TwoFactorProvider, scopes_to_string};

/// Standard scopes for user token requests: "api offline_access"
pub(crate) const STANDARD_USER_SCOPES: &[Scope] = &[Scope::Api, Scope::OfflineAccess];

/// The common payload properties to send to the /connect/token endpoint to obtain
/// tokens for a BW user.
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: Serialize + DeserializeOwned + Debug")] // Ensure T meets trait bounds
pub(crate) struct LoginApiRequest<T: Serialize + DeserializeOwned + Debug> {
    // Standard OAuth2 fields
    /// The client ID for the SDK consuming client.
    /// Note: snake_case is intentional to match the API expectations.
    pub client_id: String,

    /// The grant type for the token request.
    /// Note: snake_case is intentional to match the API expectations.
    pub grant_type: GrantType,

    /// The space-separated scopes for the token request (e.g., "api offline_access").
    pub scope: String,

    // Custom fields BW uses for user token requests
    /// The device type making the request.
    #[serde(rename = "deviceType")]
    pub device_type: DeviceType,

    /// The identifier of the device.
    #[serde(rename = "deviceIdentifier")]
    pub device_identifier: String,

    /// The name of the device.
    #[serde(rename = "deviceName")]
    pub device_name: String,

    /// The push notification registration token for mobile devices.
    #[serde(rename = "devicePushToken")]
    pub device_push_token: Option<String>,

    // Two-factor authentication fields
    /// The two-factor authentication token.
    #[serde(rename = "twoFactorToken")]
    pub two_factor_token: Option<String>,

    /// The two-factor authentication provider.
    #[serde(rename = "twoFactorProvider")]
    pub two_factor_provider: Option<TwoFactorProvider>,

    /// Whether to remember two-factor authentication on this device.
    #[serde(rename = "twoFactorRemember")]
    pub two_factor_remember: Option<bool>,

    // Specific login mechanism fields will go here (e.g., password, SSO, etc)
    #[serde(flatten)]
    pub login_mechanism_fields: T,
}

impl<T: Serialize + DeserializeOwned + Debug> LoginApiRequest<T> {
    /// Creates a new UserLoginApiRequest with standard scopes ("api offline_access").
    /// The scope can be overridden after construction if needed for specific auth flows.
    pub(crate) fn new(
        client_id: String,
        grant_type: GrantType,
        device_type: DeviceType,
        device_identifier: String,
        device_name: String,
        device_push_token: Option<String>,
        login_mechanism_fields: T,
    ) -> Self {
        Self {
            client_id,
            grant_type,
            scope: scopes_to_string(STANDARD_USER_SCOPES),
            device_type,
            device_identifier,
            device_name,
            device_push_token,
            two_factor_token: None,
            two_factor_provider: None,
            two_factor_remember: None,
            login_mechanism_fields,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test constants
    const TEST_CLIENT_ID: &str = "test-client-id";
    const TEST_DEVICE_IDENTIFIER: &str = "test-device-identifier";
    const TEST_DEVICE_NAME: &str = "Test Device";
    const TEST_DEVICE_PUSH_TOKEN: &str = "test-push-token";

    // Simple test struct for testing the generic type parameter
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct MockLoginMechanismFields {
        username: String,
        password: String,
    }

    // Another test struct to verify the generic works with different types
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct AlternativeMechanismFields {
        token: String,
    }

    #[test]
    fn test_constructor_creates_proper_defaults() {
        let mock_fields = MockLoginMechanismFields {
            username: "user@example.com".to_string(),
            password: "hashed-password".to_string(),
        };

        let request = LoginApiRequest::new(
            TEST_CLIENT_ID.to_string(),
            GrantType::Password,
            DeviceType::SDK,
            TEST_DEVICE_IDENTIFIER.to_string(),
            TEST_DEVICE_NAME.to_string(),
            Some(TEST_DEVICE_PUSH_TOKEN.to_string()),
            mock_fields,
        );

        // Verify standard scopes are set correctly
        assert_eq!(
            request.scope,
            scopes_to_string(STANDARD_USER_SCOPES),
            "Should use standard user scopes"
        );
        assert_eq!(request.scope, "api offline_access");

        // Verify 2FA fields default to None
        assert_eq!(request.two_factor_token, None);
        assert_eq!(request.two_factor_provider, None);
        assert_eq!(request.two_factor_remember, None);

        // Verify all constructor parameters are set correctly
        assert_eq!(request.client_id, TEST_CLIENT_ID);
        assert_eq!(request.grant_type, GrantType::Password);
        assert_eq!(request.device_type, DeviceType::SDK);
        assert_eq!(request.device_identifier, TEST_DEVICE_IDENTIFIER);
        assert_eq!(request.device_name, TEST_DEVICE_NAME);
        assert_eq!(
            request.device_push_token,
            Some(TEST_DEVICE_PUSH_TOKEN.to_string())
        );
    }

    #[test]
    fn test_constructor_without_device_push_token() {
        let mock_fields = MockLoginMechanismFields {
            username: "user@example.com".to_string(),
            password: "hashed-password".to_string(),
        };

        let request = LoginApiRequest::new(
            TEST_CLIENT_ID.to_string(),
            GrantType::Password,
            DeviceType::SDK,
            TEST_DEVICE_IDENTIFIER.to_string(),
            TEST_DEVICE_NAME.to_string(),
            None, // No push token
            mock_fields,
        );

        assert_eq!(request.device_push_token, None);
    }

    #[test]
    fn test_serialization_field_names() {
        let mock_fields = MockLoginMechanismFields {
            username: "user@example.com".to_string(),
            password: "hashed-password".to_string(),
        };

        let request = LoginApiRequest::new(
            TEST_CLIENT_ID.to_string(),
            GrantType::Password,
            DeviceType::SDK,
            TEST_DEVICE_IDENTIFIER.to_string(),
            TEST_DEVICE_NAME.to_string(),
            Some(TEST_DEVICE_PUSH_TOKEN.to_string()),
            mock_fields,
        );

        let serialized =
            serde_urlencoded::to_string(&request).expect("Failed to serialize LoginApiRequest");

        // Verify OAuth2 standard fields use snake_case
        assert!(
            serialized.contains("client_id="),
            "client_id should use snake_case"
        );
        assert!(
            serialized.contains("grant_type="),
            "grant_type should use snake_case"
        );
        assert!(serialized.contains("scope="), "scope should use snake_case");

        // Verify Bitwarden custom fields use camelCase
        assert!(
            serialized.contains("deviceType="),
            "device_type should serialize as deviceType"
        );
        assert!(
            serialized.contains("deviceIdentifier="),
            "device_identifier should serialize as deviceIdentifier"
        );
        assert!(
            serialized.contains("deviceName="),
            "device_name should serialize as deviceName"
        );
        assert!(
            serialized.contains("devicePushToken="),
            "device_push_token should serialize as devicePushToken"
        );
        assert!(
            !serialized.contains("device_push_token"),
            "device_push_token should not appear in snake_case"
        );

        // Verify 2FA fields use camelCase
        // Note: These are None, so they won't appear in the serialization
        // But we can verify they would use camelCase by checking field omission
        assert!(
            !serialized.contains("two_factor_token"),
            "two_factor_token should not appear in snake_case"
        );
        assert!(
            !serialized.contains("two_factor_provider"),
            "two_factor_provider should not appear in snake_case"
        );
        assert!(
            !serialized.contains("two_factor_remember"),
            "two_factor_remember should not appear in snake_case"
        );
        assert!(
            !serialized.contains("twoFactorToken"),
            "twoFactorToken should be omitted when None"
        );
        assert!(
            !serialized.contains("twoFactorProvider"),
            "twoFactorProvider should be omitted when None"
        );
        assert!(
            !serialized.contains("twoFactorRemember"),
            "twoFactorRemember should be omitted when None"
        );

        // Verify flattened login mechanism fields are present
        assert!(
            serialized.contains("username="),
            "username should be included from flattened fields"
        );
        assert!(
            serialized.contains("password="),
            "password should be included from flattened fields"
        );
    }

    #[test]
    fn test_generic_type_parameter_with_different_types() {
        // Test with MockLoginMechanismFields
        let mock_fields = MockLoginMechanismFields {
            username: "user@example.com".to_string(),
            password: "password-hash".to_string(),
        };

        let request1 = LoginApiRequest::new(
            TEST_CLIENT_ID.to_string(),
            GrantType::Password,
            DeviceType::SDK,
            TEST_DEVICE_IDENTIFIER.to_string(),
            TEST_DEVICE_NAME.to_string(),
            None,
            mock_fields,
        );

        assert_eq!(request1.login_mechanism_fields.username, "user@example.com");
        assert_eq!(request1.login_mechanism_fields.password, "password-hash");

        // Test with AlternativeMechanismFields
        let alternative_fields = AlternativeMechanismFields {
            token: "some-token".to_string(),
        };

        let request2 = LoginApiRequest::new(
            TEST_CLIENT_ID.to_string(),
            GrantType::Password,
            DeviceType::SDK,
            TEST_DEVICE_IDENTIFIER.to_string(),
            TEST_DEVICE_NAME.to_string(),
            None,
            alternative_fields,
        );

        assert_eq!(request2.login_mechanism_fields.token, "some-token");
    }

    #[test]
    fn test_serialization_with_2fa_fields() {
        let mock_fields = MockLoginMechanismFields {
            username: "user@example.com".to_string(),
            password: "hashed-password".to_string(),
        };

        let mut request = LoginApiRequest::new(
            TEST_CLIENT_ID.to_string(),
            GrantType::Password,
            DeviceType::SDK,
            TEST_DEVICE_IDENTIFIER.to_string(),
            TEST_DEVICE_NAME.to_string(),
            None,
            mock_fields,
        );

        // Manually set 2FA fields to verify they serialize correctly
        request.two_factor_token = Some("2fa-token".to_string());
        request.two_factor_provider = Some(TwoFactorProvider::Authenticator);
        request.two_factor_remember = Some(true);

        let serialized =
            serde_urlencoded::to_string(&request).expect("Failed to serialize LoginApiRequest");

        // Verify 2FA fields are present and use camelCase
        assert!(
            serialized.contains("twoFactorToken=2fa-token"),
            "2FA token should be serialized with camelCase"
        );
        assert!(
            serialized.contains("twoFactorProvider="),
            "2FA provider should be serialized with camelCase"
        );
        assert!(
            serialized.contains("twoFactorRemember=true"),
            "2FA remember should be serialized with camelCase"
        );
    }

    #[test]
    fn test_scope_can_be_overridden() {
        let mock_fields = MockLoginMechanismFields {
            username: "user@example.com".to_string(),
            password: "hashed-password".to_string(),
        };

        let mut request = LoginApiRequest::new(
            TEST_CLIENT_ID.to_string(),
            GrantType::Password,
            DeviceType::SDK,
            TEST_DEVICE_IDENTIFIER.to_string(),
            TEST_DEVICE_NAME.to_string(),
            None,
            mock_fields,
        );

        // Verify default scope
        assert_eq!(request.scope, "api offline_access");

        // Override scope for a custom auth flow
        request.scope = "custom_scope".to_string();
        assert_eq!(request.scope, "custom_scope");
    }
}
