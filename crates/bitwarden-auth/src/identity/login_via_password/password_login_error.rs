use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::identity::api::response::{
    InvalidGrantError, LoginErrorApiResponse, OAuth2ErrorApiResponse, PasswordInvalidGrantError,
};

/// Represents errors that can occur when attempting to log in.
#[bitwarden_error(basic)]
#[derive(Debug, Error)]
pub enum PasswordLoginError {
    /// The username or password provided was invalid.
    #[error("Invalid username or password provided.")]
    InvalidUsernameOrPassword,

    /// Fallback for unknown variants for forward compatibility
    #[error("Unknown password login error: {0}")]
    Unknown(String),
}

// TODO: talk with Dani about trying to avoid having every login mechanism have to implement a conversion for 2FA errors as that is common
// TODO: investigate adding a display property for each error variant that maps to unknown so we don't have to
// manually build the string each time here and in each login mechanism error file.

impl From<LoginErrorApiResponse> for PasswordLoginError {
    fn from(error: LoginErrorApiResponse) -> Self {
        match error {
            LoginErrorApiResponse::OAuth2Error(oauth_error) => match oauth_error {
                OAuth2ErrorApiResponse::InvalidGrant { error_description } => {
                    match error_description {
                        Some(InvalidGrantError::Password(
                            PasswordInvalidGrantError::InvalidUsernameOrPassword,
                        )) => Self::InvalidUsernameOrPassword,
                        Some(InvalidGrantError::Password(PasswordInvalidGrantError::Unknown)) => {
                            Self::Unknown("Invalid grant - password unknown error".to_string())
                        }
                        Some(InvalidGrantError::Unknown) => {
                            Self::Unknown("Invalid grant - unknown error".to_string())
                        }
                        None => {
                            Self::Unknown("Invalid grant with no error description".to_string())
                        }
                    }
                }
                OAuth2ErrorApiResponse::InvalidRequest { error_description } => {
                    Self::Unknown(format!(
                        "Invalid request: {}",
                        error_description.unwrap_or("no error description".to_string())
                    ))
                }
                OAuth2ErrorApiResponse::InvalidClient { error_description } => {
                    Self::Unknown(format!(
                        "Invalid client: {}",
                        error_description.unwrap_or("no error description".to_string())
                    ))
                }
                OAuth2ErrorApiResponse::UnauthorizedClient { error_description } => {
                    Self::Unknown(format!(
                        "Unauthorized client: {}",
                        error_description.unwrap_or("no error description".to_string())
                    ))
                }
                OAuth2ErrorApiResponse::UnsupportedGrantType { error_description } => {
                    Self::Unknown(format!(
                        "Unsupported grant type: {}",
                        error_description.unwrap_or("no error description".to_string())
                    ))
                }
                OAuth2ErrorApiResponse::InvalidScope { error_description } => {
                    Self::Unknown(format!(
                        "Invalid scope: {}",
                        error_description.unwrap_or("no error description".to_string())
                    ))
                }
                OAuth2ErrorApiResponse::InvalidTarget { error_description } => {
                    Self::Unknown(format!(
                        "Invalid target: {}",
                        error_description.unwrap_or("no error description".to_string())
                    ))
                }
            },
            LoginErrorApiResponse::UnexpectedError(msg) => {
                Self::Unknown(format!("Unexpected error: {}", msg))
            }
        }
    }
}
