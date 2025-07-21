use serde::Serialize;

use crate::auth::send_access::requests::enums::SendAccessCredentials;

/// Represents the shape of the payload for request
#[derive(Serialize, Debug)]
// untagged allows for different variants to be serialized without a type tag
// example: { "password_hash": "example_hash" } instead of { "Password": { "password_hash": "example_hash" } }
#[serde(untagged)]
pub enum SendAccessTokenPayloadVariant {
    /// Uses inline variant syntax for these as we don't need to reference them as independent types elsewhere.
    #[allow(missing_docs)]
    Password { password_hash: String },
    #[allow(missing_docs)]
    Email { email: String },
    #[allow(missing_docs)]
    EmailOtp { email: String, otp: String },
    /// Represents an anonymous request, which does not require credentials.
    Anonymous,
}

// Define a from trait to go from Option<SendAccessCredentials> to SendAccessTokenPayloadVariant
impl From<Option<SendAccessCredentials>> for SendAccessTokenPayloadVariant {
    fn from(credentials: Option<SendAccessCredentials>) -> Self {
        match credentials {
            Some(SendAccessCredentials::Password(credentials)) => {
                SendAccessTokenPayloadVariant::Password {
                    password_hash: credentials.password_hash,
                }
            }
            Some(SendAccessCredentials::Email(credentials)) => {
                SendAccessTokenPayloadVariant::Email {
                    email: credentials.email,
                }
            }
            Some(SendAccessCredentials::EmailOtp(credentials)) => {
                SendAccessTokenPayloadVariant::EmailOtp {
                    email: credentials.email,
                    otp: credentials.otp,
                }
            }
            None => SendAccessTokenPayloadVariant::Anonymous,
        }
    }
}
