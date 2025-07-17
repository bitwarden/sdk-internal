use serde::{Deserialize, Serialize};

/// TODO: Add a trait to this enum to allow for serialization and deserialization of the enum values.
#[derive(Serialize, Deserialize, Debug)]
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
