use serde::Serialize;

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
    Anonymous {},
}
