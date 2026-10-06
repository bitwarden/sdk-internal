use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use reqwest::StatusCode;
use thiserror::Error;

use super::validate::AccessRuleValidationError;

/// Errors returned from [`super::AccessRulesClient`] operations.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessRuleError {
    /// The request failed local validation before being sent to the server.
    #[error(transparent)]
    Validation(#[from] AccessRuleValidationError),
    /// The rule named by the request does not exist, or the caller cannot see it.
    #[error("The access rule does not exist")]
    NotFound,
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

impl AccessRuleError {
    /// Classifies a failed call that addressed one rule by id, mapping the server's `404` onto
    /// [`NotFound`](Self::NotFound) and leaving every other failure as
    /// [`Api`](Self::Api).
    ///
    /// Only the by-id calls ([`get`](super::AccessRulesClient::get),
    /// [`update`](super::AccessRulesClient::update),
    /// [`delete`](super::AccessRulesClient::delete)) route through this. On the org-scoped calls a
    /// `404` says nothing about a rule, so mapping it to a missing rule there would report the
    /// wrong thing.
    ///
    /// Without this, a caller wanting to tell "this rule is gone" from a generic failure has to
    /// match on the status code inside a stringified [`ApiError`] - which is what the web client
    /// did before this variant existed.
    pub(crate) fn from_by_id_api_error(error: ApiError) -> Self {
        match &error {
            ApiError::Response(content) if content.status == StatusCode::NOT_FOUND => {
                Self::NotFound
            }
            _ => Self::Api(error),
        }
    }
}
