//! Errors that can occur when using this SDK

pub use bitwarden_api_base::Error as ApiError;
use thiserror::Error;

/// Client is not authenticated or the session has expired.
#[derive(Debug, Error)]
#[error("The client is not authenticated or the session has expired")]
pub struct NotAuthenticatedError;

/// Client's user ID is already set.
#[derive(Debug, Error, serde::Serialize, serde::Deserialize, Clone)]
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
