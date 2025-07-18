use serde::Serialize;

use crate::auth::send_access::enums::SendAccessCredentials;

#[derive(Serialize, Debug)]
// untagged allows for different variants to be serialized without a type tag
// example: { "password_hash": "example_hash" } instead of { "Password": { "password_hash": "example_hash" } }
#[serde(untagged)]
pub enum SendAccessTokenPayloadVariant {
    /// Uses inline variant syntax for these as we don't need to reference them as independent types elsewhere.
    Password {
        password_hash: String,
    },
    Email {
        email: String,
    },
    EmailOtp {
        email: String,
        otp: String,
    },
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
