use bitwarden_core::key_management::MasterPasswordError;
use serde::Deserialize;

#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PasswordInvalidGrantError {
    /// The username or password provided was invalid.
    InvalidUsernameOrPassword,
}

// Actual 2fa rejection response for future use in TwoFactorInvalidGrantError
// {
//     "error": "invalid_grant",
//     "error_description": "Two factor required.",
//     "TwoFactorProviders": [
//         "1",
//         "3"
//     ],
//     "TwoFactorProviders2": {
//         "1": {
//             "Email": "test*****@bitwarden.com"
//         },
//         "3": {
//             "Nfc": true
//         }
//     },
//     "SsoEmail2faSessionToken": "BwSsoEmail2FaSessionToken_stuff",
//     "Email": "test*****@bitwarden.com",
//     "MasterPasswordPolicy": {
//         "MinComplexity": 4,
//         "RequireLower": false,
//         "RequireUpper": false,
//         "RequireNumbers": false,
//         "RequireSpecial": false,
//         "EnforceOnLogin": true,
//         "Object": "masterPasswordPolicy"
//     }
// }

// Use untagged so serde tries to deserialize into each variant in order.
// For "invalid_username_or_password", it tries Password(PasswordInvalidGrantError) first,
// which succeeds via the #[serde(rename_all = "snake_case")] on PasswordInvalidGrantError.
// For unknown values like "new_error_code", Password variant fails, so it falls back to
// Unknown(String).
#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(untagged)]
pub enum InvalidGrantError {
    // Password grant specific errors
    Password(PasswordInvalidGrantError),

    // TODO: other grant specific errors can go here
    // TwoFactorRequired(TwoFactorInvalidGrantError)
    /// Fallback for unknown variants for forward compatibility.
    /// Must be last in the enum due to untagged deserialization trying variants in order.
    Unknown(String),
}

/// Per RFC 6749 Section 5.2, these are the standard error responses for OAuth 2.0 token requests.
/// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "error")]
pub enum OAuth2ErrorApiResponse {
    /// Invalid request error, typically due to missing parameters for a specific
    /// credential flow. Ex. `password` is required.
    InvalidRequest {
        // we need default b/c we don't want deserialization to fail if error_description is
        // missing. we want it to be None in that case.
        #[serde(default)]
        /// The optional error description for invalid request errors.
        error_description: Option<String>,
    },

    /// Invalid grant error, typically due to invalid credentials.
    InvalidGrant {
        #[serde(default)]
        /// The optional error description for invalid grant errors.
        error_description: Option<InvalidGrantError>,
    },

    /// Invalid client error, typically due to an invalid client secret or client ID.
    InvalidClient {
        #[serde(default)]
        /// The optional error description for invalid client errors.
        error_description: Option<String>,
    },

    /// Unauthorized client error, typically due to an unauthorized client.
    UnauthorizedClient {
        #[serde(default)]
        /// The optional error description for unauthorized client errors.
        error_description: Option<String>,
    },

    /// Unsupported grant type error, typically due to an unsupported credential flow.
    UnsupportedGrantType {
        #[serde(default)]
        /// The optional error description for unsupported grant type errors.
        error_description: Option<String>,
    },

    /// Invalid scope error, typically due to an invalid scope requested.
    InvalidScope {
        #[serde(default)]
        /// The optional error description for invalid scope errors.
        error_description: Option<String>,
    },

    /// Invalid target error which is shown if the requested
    /// resource is invalid, missing, unknown, or malformed.
    InvalidTarget {
        #[serde(default)]
        /// The optional error description for invalid target errors.
        error_description: Option<String>,
    },
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
// Use untagged so serde tries each variant in order without expecting a wrapper object.
// This allows us to deserialize directly from { "error": "invalid_grant", ... } instead of
// requiring { "OAuth2Error": { "error": "invalid_grant", ... } }.
#[serde(untagged)]
pub enum LoginErrorApiResponse {
    OAuth2Error(OAuth2ErrorApiResponse),
    UnexpectedError(String),
}

// This is just a utility function so that the ? operator works correctly without manual mapping
impl From<reqwest::Error> for LoginErrorApiResponse {
    fn from(value: reqwest::Error) -> Self {
        Self::UnexpectedError(format!("{value:?}"))
    }
}

impl From<MasterPasswordError> for LoginErrorApiResponse {
    fn from(value: MasterPasswordError) -> Self {
        Self::UnexpectedError(format!("{value:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test constants for common error values
    const ERROR_INVALID_USERNAME_OR_PASSWORD: &str = "invalid_username_or_password";
    const ERROR_TYPE_INVALID_GRANT: &str = "invalid_grant";

    mod invalid_grant_error_tests {
        use serde_json::{from_str, json};

        use super::*;

        #[test]
        fn password_invalid_username_or_password_deserializes() {
            let json = format!(r#""{ERROR_INVALID_USERNAME_OR_PASSWORD}""#);
            let error: InvalidGrantError = from_str(&json).unwrap();
            assert_eq!(
                error,
                InvalidGrantError::Password(PasswordInvalidGrantError::InvalidUsernameOrPassword)
            );
        }

        #[test]
        fn unknown_error_description_maps_to_unknown() {
            let json = r#""some_new_error_code""#;
            let error: InvalidGrantError = from_str(json).unwrap();
            assert_eq!(
                error,
                InvalidGrantError::Unknown("some_new_error_code".to_string())
            );
        }

        #[test]
        fn full_invalid_grant_response_with_invalid_username_or_password() {
            let payload = json!({
                "error": ERROR_TYPE_INVALID_GRANT,
                "error_description": ERROR_INVALID_USERNAME_OR_PASSWORD
            })
            .to_string();

            let parsed: OAuth2ErrorApiResponse = from_str(&payload).unwrap();
            match parsed {
                OAuth2ErrorApiResponse::InvalidGrant { error_description } => {
                    assert_eq!(
                        error_description,
                        Some(InvalidGrantError::Password(
                            PasswordInvalidGrantError::InvalidUsernameOrPassword
                        ))
                    );
                }
                _ => panic!("expected invalid_grant"),
            }
        }

        #[test]
        fn invalid_grant_without_error_description_is_allowed() {
            let payload = json!({ "error": ERROR_TYPE_INVALID_GRANT }).to_string();
            let parsed: OAuth2ErrorApiResponse = from_str(&payload).unwrap();
            match parsed {
                OAuth2ErrorApiResponse::InvalidGrant { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected invalid_grant"),
            }
        }

        #[test]
        fn invalid_grant_null_error_description_becomes_none() {
            let payload = json!({
                "error": ERROR_TYPE_INVALID_GRANT,
                "error_description": null
            })
            .to_string();

            let parsed: OAuth2ErrorApiResponse = from_str(&payload).unwrap();
            match parsed {
                OAuth2ErrorApiResponse::InvalidGrant { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected invalid_grant"),
            }
        }

        #[test]
        fn invalid_grant_with_unknown_error_description() {
            let payload = json!({
                "error": ERROR_TYPE_INVALID_GRANT,
                "error_description": "brand_new_error_type"
            })
            .to_string();

            let parsed: OAuth2ErrorApiResponse = from_str(&payload).unwrap();
            match parsed {
                OAuth2ErrorApiResponse::InvalidGrant { error_description } => {
                    assert_eq!(
                        error_description,
                        Some(InvalidGrantError::Unknown(
                            "brand_new_error_type".to_string()
                        ))
                    );
                }
                _ => panic!("expected invalid_grant"),
            }
        }
    }

    mod login_error_api_response_tests {
        use serde_json::{from_str, json};

        use super::*;

        #[test]
        fn full_server_response_with_error_model_deserializes() {
            // This is the actual server response format with ErrorModel
            // which we don't care about but need to handle during deserialization.
            let payload = json!({
                "error": ERROR_TYPE_INVALID_GRANT,
                "error_description": ERROR_INVALID_USERNAME_OR_PASSWORD,
                "ErrorModel": {
                    "Message": "Username or password is incorrect. Try again.",
                    "Object": "error"
                }
            })
            .to_string();

            let parsed: LoginErrorApiResponse = from_str(&payload).unwrap();
            match parsed {
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidGrant {
                    error_description,
                }) => {
                    assert_eq!(
                        error_description,
                        Some(InvalidGrantError::Password(
                            PasswordInvalidGrantError::InvalidUsernameOrPassword
                        ))
                    );
                }
                _ => panic!("expected OAuth2Error(InvalidGrant)"),
            }
        }

        #[test]
        fn oauth2_error_without_error_model_deserializes() {
            let payload = json!({
                "error": ERROR_TYPE_INVALID_GRANT,
                "error_description": ERROR_INVALID_USERNAME_OR_PASSWORD
            })
            .to_string();

            let parsed: LoginErrorApiResponse = from_str(&payload).unwrap();
            match parsed {
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidGrant {
                    error_description,
                }) => {
                    assert_eq!(
                        error_description,
                        Some(InvalidGrantError::Password(
                            PasswordInvalidGrantError::InvalidUsernameOrPassword
                        ))
                    );
                }
                _ => panic!("expected OAuth2Error(InvalidGrant)"),
            }
        }

        #[test]
        fn invalid_request_error_deserializes() {
            let payload = json!({
                "error": "invalid_request",
                "error_description": "password is required"
            })
            .to_string();

            let parsed: LoginErrorApiResponse = from_str(&payload).unwrap();
            match parsed {
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidRequest {
                    error_description,
                }) => {
                    assert_eq!(error_description.as_deref(), Some("password is required"));
                }
                _ => panic!("expected OAuth2Error(InvalidRequest)"),
            }
        }

        #[test]
        fn invalid_client_error_deserializes() {
            let payload = json!({
                "error": "invalid_client",
                "error_description": "Invalid client credentials"
            })
            .to_string();

            let parsed: LoginErrorApiResponse = from_str(&payload).unwrap();
            match parsed {
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidClient {
                    error_description,
                }) => {
                    assert_eq!(
                        error_description.as_deref(),
                        Some("Invalid client credentials")
                    );
                }
                _ => panic!("expected OAuth2Error(InvalidClient)"),
            }
        }

        #[test]
        fn unauthorized_client_error_deserializes() {
            let payload = json!({
                "error": "unauthorized_client"
            })
            .to_string();

            let parsed: LoginErrorApiResponse = from_str(&payload).unwrap();
            match parsed {
                LoginErrorApiResponse::OAuth2Error(
                    OAuth2ErrorApiResponse::UnauthorizedClient { error_description },
                ) => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected OAuth2Error(UnauthorizedClient)"),
            }
        }

        #[test]
        fn unsupported_grant_type_error_deserializes() {
            let payload = json!({
                "error": "unsupported_grant_type",
                "error_description": "This grant type is not supported"
            })
            .to_string();

            let parsed: LoginErrorApiResponse = from_str(&payload).unwrap();
            match parsed {
                LoginErrorApiResponse::OAuth2Error(
                    OAuth2ErrorApiResponse::UnsupportedGrantType { error_description },
                ) => {
                    assert_eq!(
                        error_description.as_deref(),
                        Some("This grant type is not supported")
                    );
                }
                _ => panic!("expected OAuth2Error(UnsupportedGrantType)"),
            }
        }

        #[test]
        fn invalid_scope_error_deserializes() {
            let payload = json!({
                "error": "invalid_scope"
            })
            .to_string();

            let parsed: LoginErrorApiResponse = from_str(&payload).unwrap();
            match parsed {
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidScope {
                    error_description,
                }) => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected OAuth2Error(InvalidScope)"),
            }
        }

        #[test]
        fn invalid_target_error_deserializes() {
            let payload = json!({
                "error": "invalid_target",
                "error_description": "Resource not found"
            })
            .to_string();

            let parsed: LoginErrorApiResponse = from_str(&payload).unwrap();
            match parsed {
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidTarget {
                    error_description,
                }) => {
                    assert_eq!(error_description.as_deref(), Some("Resource not found"));
                }
                _ => panic!("expected OAuth2Error(InvalidTarget)"),
            }
        }

        #[test]
        fn missing_or_null_error_description_deserializes_to_none() {
            // Test both missing field and null value
            let test_cases = vec![
                json!({ "error": ERROR_TYPE_INVALID_GRANT }),
                json!({ "error": ERROR_TYPE_INVALID_GRANT, "error_description": null }),
            ];

            for payload in test_cases {
                let parsed: LoginErrorApiResponse = from_str(&payload.to_string()).unwrap();
                match parsed {
                    LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidGrant {
                        error_description,
                    }) => {
                        assert!(error_description.is_none());
                    }
                    _ => panic!("expected OAuth2Error(InvalidGrant)"),
                }
            }
        }

        #[test]
        fn unknown_error_description_value_maps_to_unknown() {
            let payload = json!({
                "error": ERROR_TYPE_INVALID_GRANT,
                "error_description": "some_future_error_code"
            })
            .to_string();

            let parsed: LoginErrorApiResponse = from_str(&payload).unwrap();
            match parsed {
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidGrant {
                    error_description,
                }) => {
                    assert_eq!(
                        error_description,
                        Some(InvalidGrantError::Unknown(
                            "some_future_error_code".to_string()
                        ))
                    );
                }
                _ => panic!("expected OAuth2Error(InvalidGrant)"),
            }
        }

        #[test]
        fn error_with_extra_fields_ignores_them() {
            let payload = json!({
                "error": ERROR_TYPE_INVALID_GRANT,
                "error_description": ERROR_INVALID_USERNAME_OR_PASSWORD,
                "extra_field": "should be ignored",
                "another_field": 123,
                "ErrorModel": {
                    "Message": "Some message",
                    "Object": "error"
                }
            })
            .to_string();

            let parsed: LoginErrorApiResponse = from_str(&payload).unwrap();
            match parsed {
                LoginErrorApiResponse::OAuth2Error(OAuth2ErrorApiResponse::InvalidGrant {
                    error_description,
                }) => {
                    assert_eq!(
                        error_description,
                        Some(InvalidGrantError::Password(
                            PasswordInvalidGrantError::InvalidUsernameOrPassword
                        ))
                    );
                }
                _ => panic!("expected OAuth2Error(InvalidGrant)"),
            }
        }
    }
}
