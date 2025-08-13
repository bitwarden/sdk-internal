#[cfg(feature = "wasm")]
use tsify::Tsify;

/// Credentials for sending password secured access requests.
/// Clone auto implements the standard lib's Clone trait, allowing us to create copies of this
/// struct.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendPasswordCredentials {
    /// A Base64-encoded hash of the password protecting the send.
    pub password_hash_b64: String,
}

/// Credentials for sending an OTP to the user's email address.
/// This is used when the send requires email verification with an OTP.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendEmailCredentials {
    /// The email address to which the OTP will be sent.
    pub email: String,
}

/// Credentials for getting a send access token using an email and OTP.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendEmailOtpCredentials {
    /// The email address to which the OTP will be sent.
    pub email: String,
    /// The one-time password (OTP) that the user has received via email.
    pub otp: String,
}

/// The credentials used for send access requests.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
// Use untagged so that each variant can be serialized without a type tag.
// For example, this allows us to serialize the password credentials as just
// {"password_hash_b64": "value"} instead of {"type": "password", "password_hash_b64": "value"}.
#[serde(untagged)]
pub enum SendAccessCredentials {
    #[allow(missing_docs)]
    Password(SendPasswordCredentials),
    #[allow(missing_docs)]
    Email(SendEmailCredentials),
    #[allow(missing_docs)]
    EmailOtp(SendEmailOtpCredentials),
}

/// A request structure for requesting a send access token from the API.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendAccessTokenRequest {
    /// The id of the send for which the access token is requested.
    pub send_id: String,

    /// The optional send access credentials.
    pub send_access_credentials: Option<SendAccessCredentials>,
}

#[cfg(test)]
mod tests {
    use super::*;

    mod send_access_credentials_tests {
        use serde_json;

        use super::*;

        #[test]
        fn serialize_password_credentials() {
            let creds = SendAccessCredentials::Password(SendPasswordCredentials {
                password_hash_b64: "ha$h".into(),
            });
            let json = serde_json::to_string(&creds).unwrap();
            assert_eq!(json, r#"{"password_hash_b64":"ha$h"}"#);
        }

        #[test]
        fn serialize_email_credentials() {
            let creds = SendAccessCredentials::Email(SendEmailCredentials {
                email: "user@example.com".into(),
            });
            let json = serde_json::to_string(&creds).unwrap();
            assert_eq!(json, r#"{"email":"user@example.com"}"#);
        }

        #[test]
        fn serialize_email_otp_credentials() {
            let creds = SendAccessCredentials::EmailOtp(SendEmailOtpCredentials {
                email: "user@example.com".into(),
                otp: "123456".into(),
            });
            let json = serde_json::to_string(&creds).unwrap();
            assert_eq!(json, r#"{"email":"user@example.com","otp":"123456"}"#);
        }
    }
}
