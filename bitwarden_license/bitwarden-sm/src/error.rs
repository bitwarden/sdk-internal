use bitwarden_api_api::apis::Error as ApiApisError;
use log::debug;
use thiserror::Error;
use validator::ValidationErrors;

#[derive(Debug, thiserror::Error)]
pub enum SecretsManagerError {
    #[error(transparent)]
    ValidationError(ValidationError),
    #[error(transparent)]
    VaultLocked(#[from] bitwarden_core::VaultLockedError),
    #[error(transparent)]
    CryptoError(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    Chrono(#[from] chrono::ParseError),

    #[error(transparent)]
    ApiError(#[from] bitwarden_core::ApiError),
    #[error(transparent)]
    MissingFieldError(#[from] bitwarden_core::MissingFieldError),
}

// Validation
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("{0} must not be empty")]
    Required(String),
    #[error("{0} must not exceed {1} characters in length")]
    ExceedsCharacterLength(String, u64),
    #[error("{0} must not contain only whitespaces")]
    OnlyWhitespaces(String),
    #[error("Unknown validation error: {0}")]
    Unknown(String),
}

const VALIDATION_LENGTH_CODE: &str = "length";
const VALIDATION_ONLY_WHITESPACES_CODE: &str = "only_whitespaces";

pub fn validate_only_whitespaces(value: &str) -> Result<(), validator::ValidationError> {
    if !value.is_empty() && value.trim().is_empty() {
        return Err(validator::ValidationError::new(
            VALIDATION_ONLY_WHITESPACES_CODE,
        ));
    }
    Ok(())
}

impl From<ValidationErrors> for ValidationError {
    fn from(e: ValidationErrors) -> Self {
        debug!("Validation errors: {e:#?}");
        for (field_name, errors) in e.field_errors() {
            for error in errors {
                match error.code.as_ref() {
                    VALIDATION_LENGTH_CODE => {
                        if error.params.contains_key("min")
                            && error.params["min"].as_u64().expect("Min provided") == 1
                            && error.params["value"]
                                .as_str()
                                .expect("Value provided")
                                .is_empty()
                        {
                            return ValidationError::Required(field_name.to_string());
                        } else if error.params.contains_key("max") {
                            return ValidationError::ExceedsCharacterLength(
                                field_name.to_string(),
                                error.params["max"].as_u64().expect("Max provided"),
                            );
                        }
                    }
                    VALIDATION_ONLY_WHITESPACES_CODE => {
                        return ValidationError::OnlyWhitespaces(field_name.to_string());
                    }
                    _ => {}
                }
            }
        }
        ValidationError::Unknown(format!("{e:#?}"))
    }
}

impl From<ValidationErrors> for SecretsManagerError {
    fn from(e: ValidationErrors) -> Self {
        SecretsManagerError::ValidationError(e.into())
    }
}

impl<T> From<ApiApisError<T>> for SecretsManagerError {
    fn from(e: bitwarden_api_api::apis::Error<T>) -> Self {
        SecretsManagerError::ApiError(e.into())
    }
}
