use serde::Serialize;

use crate::auth::send_access::requests::enums::SendAccessCredentials;

/// Represents the shape of the credentials used in the send access token payload.
#[derive(Serialize, Debug)]
// untagged allows for different variants to be serialized without a type tag
// example: { "password_hash": "example_hash" } instead of { "Password": { "password_hash": "example_hash" } }
#[serde(untagged)]
pub enum SendAccessTokenPayloadCredentials {
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

/// Defines a from trait that converts `SendAccessCredentials` into `SendAccessTokenPayloadCredentials`.
impl From<Option<SendAccessCredentials>> for SendAccessTokenPayloadCredentials {
    fn from(credentials: Option<SendAccessCredentials>) -> Self {
        match credentials {
            Some(SendAccessCredentials::Password(credentials)) => {
                SendAccessTokenPayloadCredentials::Password {
                    password_hash: credentials.password_hash,
                }
            }
            Some(SendAccessCredentials::Email(credentials)) => {
                SendAccessTokenPayloadCredentials::Email {
                    email: credentials.email,
                }
            }
            Some(SendAccessCredentials::EmailOtp(credentials)) => {
                SendAccessTokenPayloadCredentials::EmailOtp {
                    email: credentials.email,
                    otp: credentials.otp,
                }
            }
            None => SendAccessTokenPayloadCredentials::Anonymous,
        }
    }
}
