use bitwarden_core::key_management::MasterPasswordError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::identity::api::response::{
    InvalidGrantError, LoginErrorApiResponse, OAuth2ErrorApiResponse, PasswordInvalidGrantError,
};

/// Represents errors that can occur when attempting to log in.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum PasswordLoginError {
    /// The username or password provided was invalid.
    #[error("Invalid username or password provided.")]
    InvalidUsernameOrPassword,

    /// Error deriving password authentication data.
    /// This can occur if the KDF configuration is invalid or corrupted.
    #[error(transparent)]
    PasswordAuthenticationDataDerivation(#[from] MasterPasswordError),

    /// Fallback for unknown variants for forward compatibility
    #[error("Unknown password login error: {0}")]
    Unknown(String),
}

// TODO: When adding 2FA support, consider how we can avoid having each login mechanism have to implement a conversion for 2FA errors
// TODO: per discussion with Dani, investigate adding a display property for each error variant that maps to unknown so we don't have to
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
                        Some(InvalidGrantError::Unknown(error_code)) => {
                            Self::Unknown(format!("Invalid grant - unknown error: {}", error_code))
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

#[cfg(test)]
mod tests {
    use super::*;

    // Test constants for strings used multiple times
    const ERROR_DESC_NO_DESCRIPTION: &str = "no error description";
    const TEST_ERROR_DESC: &str = "Test error description";

    mod from_login_error_api_response {
        use super::*;

        #[test]
        fn invalid_grant_with_invalid_username_or_password() {
            let api_error =
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidGrant {
                    error_description: Some(InvalidGrantError::Password(
                        PasswordInvalidGrantError::InvalidUsernameOrPassword,
                    )),
                });

            let result: PasswordLoginError = api_error.into();

            assert!(matches!(
                result,
                PasswordLoginError::InvalidUsernameOrPassword
            ));
        }

        #[test]
        fn invalid_grant_with_unknown_error() {
            let api_error =
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidGrant {
                    error_description: Some(InvalidGrantError::Unknown(
                        "unknown_error_code".to_string(),
                    )),
                });

            let result: PasswordLoginError = api_error.into();

            match result {
                PasswordLoginError::Unknown(msg) => {
                    assert_eq!(msg, "Invalid grant - unknown error: unknown_error_code");
                }
                _ => panic!("Expected Unknown variant"),
            }
        }

        #[test]
        fn invalid_grant_with_no_error_description() {
            let api_error =
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidGrant {
                    error_description: None,
                });

            let result: PasswordLoginError = api_error.into();

            match result {
                PasswordLoginError::Unknown(msg) => {
                    assert_eq!(msg, "Invalid grant with no error description");
                }
                _ => panic!("Expected Unknown variant"),
            }
        }

        #[test]
        fn invalid_request_with_error_description() {
            let api_error =
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidRequest {
                    error_description: Some(TEST_ERROR_DESC.to_string()),
                });

            let result: PasswordLoginError = api_error.into();

            match result {
                PasswordLoginError::Unknown(msg) => {
                    assert_eq!(msg, format!("Invalid request: {}", TEST_ERROR_DESC));
                }
                _ => panic!("Expected Unknown variant"),
            }
        }

        #[test]
        fn invalid_request_without_error_description() {
            let api_error =
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidRequest {
                    error_description: None,
                });

            let result: PasswordLoginError = api_error.into();

            match result {
                PasswordLoginError::Unknown(msg) => {
                    assert_eq!(
                        msg,
                        format!("Invalid request: {}", ERROR_DESC_NO_DESCRIPTION)
                    );
                }
                _ => panic!("Expected Unknown variant"),
            }
        }

        #[test]
        fn invalid_client_with_error_description() {
            let api_error =
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidClient {
                    error_description: Some(TEST_ERROR_DESC.to_string()),
                });

            let result: PasswordLoginError = api_error.into();

            match result {
                PasswordLoginError::Unknown(msg) => {
                    assert_eq!(msg, format!("Invalid client: {}", TEST_ERROR_DESC));
                }
                _ => panic!("Expected Unknown variant"),
            }
        }

        #[test]
        fn invalid_client_without_error_description() {
            let api_error =
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidClient {
                    error_description: None,
                });

            let result: PasswordLoginError = api_error.into();

            match result {
                PasswordLoginError::Unknown(msg) => {
                    assert_eq!(
                        msg,
                        format!("Invalid client: {}", ERROR_DESC_NO_DESCRIPTION)
                    );
                }
                _ => panic!("Expected Unknown variant"),
            }
        }

        #[test]
        fn unauthorized_client_with_error_description() {
            let api_error =
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::UnauthorizedClient {
                    error_description: Some(TEST_ERROR_DESC.to_string()),
                });

            let result: PasswordLoginError = api_error.into();

            match result {
                PasswordLoginError::Unknown(msg) => {
                    assert_eq!(msg, format!("Unauthorized client: {}", TEST_ERROR_DESC));
                }
                _ => panic!("Expected Unknown variant"),
            }
        }

        #[test]
        fn unauthorized_client_without_error_description() {
            let api_error =
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::UnauthorizedClient {
                    error_description: None,
                });

            let result: PasswordLoginError = api_error.into();

            match result {
                PasswordLoginError::Unknown(msg) => {
                    assert_eq!(
                        msg,
                        format!("Unauthorized client: {}", ERROR_DESC_NO_DESCRIPTION)
                    );
                }
                _ => panic!("Expected Unknown variant"),
            }
        }

        #[test]
        fn unsupported_grant_type_with_error_description() {
            let api_error =
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::UnsupportedGrantType {
                    error_description: Some(TEST_ERROR_DESC.to_string()),
                });

            let result: PasswordLoginError = api_error.into();

            match result {
                PasswordLoginError::Unknown(msg) => {
                    assert_eq!(msg, format!("Unsupported grant type: {}", TEST_ERROR_DESC));
                }
                _ => panic!("Expected Unknown variant"),
            }
        }

        #[test]
        fn unsupported_grant_type_without_error_description() {
            let api_error =
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::UnsupportedGrantType {
                    error_description: None,
                });

            let result: PasswordLoginError = api_error.into();

            match result {
                PasswordLoginError::Unknown(msg) => {
                    assert_eq!(
                        msg,
                        format!("Unsupported grant type: {}", ERROR_DESC_NO_DESCRIPTION)
                    );
                }
                _ => panic!("Expected Unknown variant"),
            }
        }

        #[test]
        fn invalid_scope_with_error_description() {
            let api_error =
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidScope {
                    error_description: Some(TEST_ERROR_DESC.to_string()),
                });

            let result: PasswordLoginError = api_error.into();

            match result {
                PasswordLoginError::Unknown(msg) => {
                    assert_eq!(msg, format!("Invalid scope: {}", TEST_ERROR_DESC));
                }
                _ => panic!("Expected Unknown variant"),
            }
        }

        #[test]
        fn invalid_scope_without_error_description() {
            let api_error =
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidScope {
                    error_description: None,
                });

            let result: PasswordLoginError = api_error.into();

            match result {
                PasswordLoginError::Unknown(msg) => {
                    assert_eq!(msg, format!("Invalid scope: {}", ERROR_DESC_NO_DESCRIPTION));
                }
                _ => panic!("Expected Unknown variant"),
            }
        }

        #[test]
        fn invalid_target_with_error_description() {
            let api_error =
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidTarget {
                    error_description: Some(TEST_ERROR_DESC.to_string()),
                });

            let result: PasswordLoginError = api_error.into();

            match result {
                PasswordLoginError::Unknown(msg) => {
                    assert_eq!(msg, format!("Invalid target: {}", TEST_ERROR_DESC));
                }
                _ => panic!("Expected Unknown variant"),
            }
        }

        #[test]
        fn invalid_target_without_error_description() {
            let api_error =
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidTarget {
                    error_description: None,
                });

            let result: PasswordLoginError = api_error.into();

            match result {
                PasswordLoginError::Unknown(msg) => {
                    assert_eq!(
                        msg,
                        format!("Invalid target: {}", ERROR_DESC_NO_DESCRIPTION)
                    );
                }
                _ => panic!("Expected Unknown variant"),
            }
        }

        #[test]
        fn unexpected_error() {
            let api_error = LoginErrorApiResponse::UnexpectedError("Network timeout".to_string());

            let result: PasswordLoginError = api_error.into();

            match result {
                PasswordLoginError::Unknown(msg) => {
                    assert_eq!(msg, "Unexpected error: Network timeout");
                }
                _ => panic!("Expected Unknown variant"),
            }
        }
    }
}
