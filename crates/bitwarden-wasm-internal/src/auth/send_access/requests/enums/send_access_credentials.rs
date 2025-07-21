/// Credentials for sending password secured access requests.
/// Clone auto implements the standard lib's Clone trait, allowing us to create copies of this struct.
#[derive(serde::Serialize, Clone)]
pub struct SendPasswordCredentials {
    /// A hashed representation of the password protecting the send.
    pub password_hash: String,
}

/// Credentials for sending an OTP to the user's email address.
/// This is used when the send requires email verification with an OTP.
#[derive(serde::Serialize, Clone)]
pub struct SendEmailCredentials {
    /// The email address to which the OTP will be sent.
    pub email: String,
}

/// Credentials for getting a send access token using an email and OTP.
#[derive(serde::Serialize, Clone)]
pub struct SendEmailOtpCredentials {
    /// The email address to which the OTP will be sent.
    pub email: String,
    /// The one-time password (OTP) that the user has received via email.
    pub otp: String,
}

/// The credentials used for send access requests.
#[derive(serde::Serialize, Clone)]
// Use untagged so that each variant can be serialized without a type tag.
// For example, this allows us to serialize the password credentials as just
// {"password_hash": "value"} instead of {"type": "password", "password_hash": "value"}.
#[serde(untagged)]
pub enum SendAccessCredentials {
    #[allow(missing_docs)]
    Password(SendPasswordCredentials),
    #[allow(missing_docs)]
    Email(SendEmailCredentials),
    #[allow(missing_docs)]
    EmailOtp(SendEmailOtpCredentials),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn serialize_password_credentials() {
        let creds = SendAccessCredentials::Password(SendPasswordCredentials {
            password_hash: "ha$h".into(),
        });
        let json = serde_json::to_string(&creds).unwrap();
        assert_eq!(json, r#"{"password_hash":"ha$h"}"#);
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
