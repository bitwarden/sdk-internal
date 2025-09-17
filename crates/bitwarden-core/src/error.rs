//! Errors that can occur when using this SDK

use std::fmt::Debug;

use bitwarden_api_api::apis::Error as ApiApisError;
use bitwarden_api_identity::apis::Error as IdentityError;
#[cfg(feature = "internal")]
use bitwarden_error::bitwarden_error;
use reqwest::StatusCode;
use thiserror::Error;

macro_rules! impl_bitwarden_error {
    ($name:ident, $error:ident) => {
        impl<T> From<$name<T>> for $error {
            fn from(e: $name<T>) -> Self {
                match e {
                    $name::Reqwest(e) => Self::Reqwest(e),
                    $name::ResponseError(e) => Self::ResponseContent {
                        status: e.status,
                        message: e.content,
                    },
                    $name::Serde(e) => Self::Serde(e),
                    $name::Io(e) => Self::Io(e),
                }
            }
        }
    };
}

/// Errors from performing network requests.
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum ApiError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("Received error message from server: [{}] {}", .status, .message)]
    ResponseContent { status: StatusCode, message: String },
}

impl_bitwarden_error!(ApiApisError, ApiError);
impl_bitwarden_error!(IdentityError, ApiError);

/// Client is not authenticated or the session has expired.
#[derive(Debug, Error)]
#[error("The client is not authenticated or the session has expired")]
pub struct NotAuthenticatedError;

/// Client's user ID is already set.
#[derive(Debug, Error)]
#[error("The client user ID is already set")]
pub struct UserIdAlreadySetError;

/// Missing required field.
#[derive(Debug, Error)]
#[error("The response received was missing a required field: {0}")]
pub struct MissingFieldError(pub &'static str);

/// Wrong password.
#[derive(Debug, thiserror::Error)]
#[error("Wrong password")]
pub struct WrongPasswordError;

/// Missing private key.
#[derive(Debug, thiserror::Error)]
#[error("Missing private key")]
pub struct MissingPrivateKeyError;

/// Signifies that the state is invalid from a cryptographic perspective, such as a required
/// security value missing, or being invalid
#[cfg(feature = "internal")]
#[bitwarden_error(flat)]
#[derive(Debug, thiserror::Error)]
pub enum StatefulCryptoError {
    /// The security state is not present, but required for this user. V2 users must always
    /// have a security state, V1 users cannot have a security state.
    #[error("Security state is required, but missing")]
    MissingSecurityState,
    /// The function expected a user in a account cryptography version, but got a different one.
    #[error("Expected user in account cryptography version {expected}, but got {got}")]
    WrongAccountCryptoVersion {
        /// The expected account cryptography version. This can include a range, such as `2+`.
        expected: String,
        /// The actual account cryptography version.
        got: u32,
    },
    #[error("Crypto error, {0}")]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

/// This macro is used to require that a value is present or return an error otherwise.
/// It is equivalent to using `val.ok_or(Error::MissingFields)?`, but easier to use and
/// with a more descriptive error message.
/// Note that this macro will return early from the function if the value is not present.
#[macro_export]
macro_rules! require {
    ($val:expr) => {
        match $val {
            Some(val) => val,
            None => return Err($crate::MissingFieldError(stringify!($val)).into()),
        }
    };
}
