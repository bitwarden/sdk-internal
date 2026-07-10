use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use super::validate::AccessRuleValidationError;

/// Errors returned from [`super::AccessRulesClient`] operations.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessRuleError {
    /// The request failed local validation before being sent to the server.
    #[error(transparent)]
    Validation(#[from] AccessRuleValidationError),
    /// The `conditions` field of a server response could not be interpreted.
    #[error("Invalid conditions: {0}")]
    InvalidConditions(String),
    /// The server response was missing a field required to build the requested type.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// A date field in the server response could not be parsed.
    #[error(transparent)]
    Chrono(#[from] chrono::ParseError),
    /// A network or (de)serialization error occurred while calling the server.
    #[error(transparent)]
    Api(#[from] ApiError),
}
