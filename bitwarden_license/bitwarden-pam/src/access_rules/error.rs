use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use reqwest::StatusCode;
use thiserror::Error;

use super::validate::AccessRuleValidationError;
use crate::problem;

/// Errors returned from [`super::AccessRulesClient`] operations.
///
/// The named write failures each correspond to one stable code in the server's problem response;
/// see [`from_code`](Self::from_code) for the mapping. A code this SDK version does not recognize
/// stays [`Api`](Self::Api), so a server that grows one never needs a client release to be safe.
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

    /// The rule has no name. Rules are picked out by name wherever they are listed.
    #[error("Name is required")]
    NameRequired,
    /// Another rule in the same organization already has this name, compared case-insensitively.
    #[error("A rule with that name already exists")]
    NameTaken,
    /// The rule allows extensions without capping them, which would leave every extension
    /// unbounded.
    #[error("A maximum extension length is required when extensions are allowed")]
    ExtensionLengthRequired,
    /// The rule's default lease duration is zero or negative.
    #[error("The default lease duration must be a positive value")]
    DefaultDurationMustBePositive,
    /// The rule's maximum lease duration is zero or negative.
    #[error("The maximum lease duration must be a positive value")]
    MaxDurationMustBePositive,
    /// The rule pre-fills requests with a duration its own cap would then refuse, so every request
    /// against it would fail at submit.
    #[error("The default lease duration cannot exceed the maximum lease duration")]
    DefaultDurationExceedsMax,
    /// The server refused the conditions document. Distinct from
    /// [`InvalidConditions`](Self::InvalidConditions), which is this SDK failing to read a document
    /// the server sent back.
    #[error("The access rule's conditions were rejected")]
    ConditionsRejected,
    /// One or more of the collections the rule would govern does not exist.
    #[error("One or more collections could not be found")]
    CollectionsMissing,
    /// One or more of the collections the rule would govern belongs to another organization.
    #[error("One or more collections do not belong to this organization")]
    CollectionsForeign,
    /// One or more of the collections the rule would govern is already governed by a different
    /// rule. A collection has at most one access rule.
    #[error("One or more collections are already governed by another access rule")]
    CollectionsAlreadyGoverned,
    /// The server response was missing a field required to build the requested type.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// A date field in the server response could not be parsed.
    #[error(transparent)]
    Chrono(#[from] chrono::ParseError),
    /// A network or (de)serialization error occurred while calling the server, or the server
    /// refused with a code this SDK version does not recognize.
    #[error(transparent)]
    Api(ApiError),
}

impl AccessRuleError {
    /// The server's codes, in the order the access-rule write paths can produce them.
    fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "rule_name_required" => Self::NameRequired,
            "rule_name_taken" => Self::NameTaken,
            "extension_length_required" => Self::ExtensionLengthRequired,
            "rule_default_duration_must_be_positive" => Self::DefaultDurationMustBePositive,
            "rule_max_duration_must_be_positive" => Self::MaxDurationMustBePositive,
            "rule_default_duration_exceeds_max" => Self::DefaultDurationExceedsMax,
            "rule_invalid_conditions" => Self::ConditionsRejected,
            "collections_missing" => Self::CollectionsMissing,
            "collections_foreign" => Self::CollectionsForeign,
            "collections_already_governed" => Self::CollectionsAlreadyGoverned,
            _ => return None,
        })
    }

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
            _ => error.into(),
        }
    }
}

/// Classifies every failed call on this surface. A code is unambiguous wherever it appears, unlike
/// a status - which is why the `404` rule above stays pinned to the by-id calls and this does not.
impl From<ApiError> for AccessRuleError {
    fn from(error: ApiError) -> Self {
        problem::classify(&error, Self::from_code).unwrap_or(Self::Api(error))
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::ResponseContent;
    use reqwest::StatusCode;

    use super::*;

    fn problem(code: &str) -> ApiError {
        ApiError::Response(ResponseContent {
            status: StatusCode::BAD_REQUEST,
            message: format!(r#"{{"errors":{{"code":[{{"type":"{code}"}}]}}}}"#),
        })
    }

    #[test]
    fn a_write_failure_becomes_its_own_variant() {
        let error: AccessRuleError = problem("collections_already_governed").into();

        assert!(matches!(error, AccessRuleError::CollectionsAlreadyGoverned));
    }

    #[test]
    fn a_code_is_read_even_on_a_by_id_call_that_did_not_404() {
        let error = AccessRuleError::from_by_id_api_error(problem("rule_name_taken"));

        assert!(matches!(error, AccessRuleError::NameTaken));
    }

    #[test]
    fn a_by_id_404_still_wins_over_the_code_reader() {
        let error = AccessRuleError::from_by_id_api_error(ApiError::Response(ResponseContent {
            status: StatusCode::NOT_FOUND,
            message: String::new(),
        }));

        assert!(matches!(error, AccessRuleError::NotFound));
    }

    #[test]
    fn an_unrecognized_code_stays_untyped() {
        let error: AccessRuleError = problem("invented_next_year").into();

        assert!(matches!(error, AccessRuleError::Api(_)));
    }
}
