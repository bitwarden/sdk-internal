/// Credentials for sending password secured access requests.
#[derive(serde::Serialize)]
pub struct SendPasswordCredentials {
    pub password_hash: String,
}

/// Credentials for sending an OTP to the user's email address.
/// This is used when the send requires email verification with an OTP.
#[derive(serde::Serialize)]
pub struct SendEmailCredentials {
    pub email: String,
}

/// Credentials for getting a send access token using an email and OTP.
#[derive(serde::Serialize)]
pub struct SendEmailOtpCredentials {
    pub email: String,
    pub otp: String,
}

#[derive(serde::Serialize)]
// Use untagged so that each variant can be serialized without a type tag.
// For example, this allows us to serialize the password credentials as just
// {"password_hash": "value"} instead of {"type": "password", "password_hash": "value"}.
#[serde(untagged)]
pub enum SendAccessCredentials {
    Password(SendPasswordCredentials),
    Email(SendEmailCredentials),
    EmailOtp(SendEmailOtpCredentials),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn serialize_password_credentials() {
        let creds = SendAccessCredentials::Password(SendPasswordCredentials {
            password_hash: "password-hash".into(),
        });
        let json = serde_json::to_string(&creds).unwrap();
        assert_eq!(json, r#"{"password_hash":"password-hash"}"#);
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
