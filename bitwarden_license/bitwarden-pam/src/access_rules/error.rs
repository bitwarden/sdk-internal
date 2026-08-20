//! The access-rule surface splits three ways: reading a rule, writing one, and deleting one.
//!
//! Unlike the other PAM surfaces this one does not use [`PamReadError`](crate::PamReadError),
//! because a rule response carries a `conditions` document the SDK interprets itself - a decode
//! failure this crate's shared decode error has no variant for.
//!
//! The write codes come from `AccessRuleWriteValidator`, which backs both `CreateAccessRuleCommand`
//! and `UpdateAccessRuleCommand`, so those two share a set. A code this SDK version does not
//! recognize stays `Api`, so a server that grows a code never needs a client release to be safe.

use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use reqwest::StatusCode;
use thiserror::Error;

use super::validate::AccessRuleValidationError;
use crate::problem;

/// Errors from turning an access-rule response into an [`AccessRuleView`](super::AccessRuleView).
///
/// Separate from this crate's [`PamDecodeError`](crate::PamDecodeError) because a rule response
/// carries a `conditions` document the SDK interprets itself, which the shared decode error has no
/// variant for. Both [`AccessRuleReadError`] and [`AccessRuleWriteError`] wrap it, so a decode
/// failure reads the same whichever call hit it.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessRuleDecodeError {
    /// The `conditions` field of a server response could not be interpreted.
    #[error("Invalid conditions: {0}")]
    InvalidConditions(String),
    /// The server response was missing a field required to build the requested type.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// A date field in the server response could not be parsed.
    #[error(transparent)]
    Chrono(#[from] chrono::ParseError),
}

/// Errors from the access-rule reads, [`list`](super::AccessRulesClient::list) and
/// [`get`](super::AccessRulesClient::get).
///
/// [`NotFound`](Self::NotFound) is reachable only from `get`: it comes from the server's `404`, and
/// on the org-scoped `list` a `404` says nothing about a rule, so there it stays
/// [`Api`](Self::Api).
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessRuleReadError {
    /// The rule named by the request does not exist, or the caller cannot see it.
    #[error("The access rule does not exist")]
    NotFound,
    /// An access-rule response could not be decoded into a view.
    #[error(transparent)]
    Decode(#[from] AccessRuleDecodeError),
    /// A network or (de)serialization error occurred while calling the server.
    #[error(transparent)]
    Api(ApiError),
}

impl AccessRuleReadError {
    /// Maps the server's `404` onto [`NotFound`](Self::NotFound). See
    /// [`AccessRuleWriteError::from_by_id_api_error`] for why this is pinned to the by-id calls.
    pub(crate) fn from_by_id_api_error(error: ApiError) -> Self {
        match &error {
            ApiError::Response(content) if content.status == StatusCode::NOT_FOUND => {
                Self::NotFound
            }
            _ => Self::Api(error),
        }
    }
}

impl From<ApiError> for AccessRuleReadError {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

/// Errors from the access-rule writes: [`create`](super::AccessRulesClient::create),
/// [`update`](super::AccessRulesClient::update) and
/// [`set_enabled`](super::AccessRulesClient::set_enabled).
///
/// The three share a set because they share a validator server-side. [`NotFound`](Self::NotFound)
/// is reachable only from the two that name a rule by id - `create` has no id to miss.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessRuleWriteError {
    /// The request failed local validation before being sent to the server.
    #[error(transparent)]
    Validation(#[from] AccessRuleValidationError),
    /// The rule named by the request does not exist, or the caller cannot see it.
    #[error("The access rule does not exist")]
    NotFound,

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
    /// [`AccessRuleDecodeError::InvalidConditions`], which is this SDK failing to read a document
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

    /// An access-rule response could not be decoded into a view.
    #[error(transparent)]
    Decode(#[from] AccessRuleDecodeError),
    /// A network or (de)serialization error occurred while calling the server, or the server
    /// refused with a code this SDK version does not recognize.
    #[error(transparent)]
    Api(ApiError),
}

impl AccessRuleWriteError {
    /// The codes `AccessRuleWriteValidator` can return.
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
    /// [`NotFound`](Self::NotFound) and reading the codes out of anything else.
    ///
    /// Only the by-id calls route through this. On an org-scoped call a `404` says nothing about a
    /// rule, so mapping it to a missing rule there would report the wrong thing.
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

/// Classifies every failed write on this surface. A code is unambiguous wherever it appears, unlike
/// a status - which is why the `404` rule above stays pinned to the by-id calls and this does not.
impl From<ApiError> for AccessRuleWriteError {
    fn from(error: ApiError) -> Self {
        problem::classify(&error, Self::from_code).unwrap_or(Self::Api(error))
    }
}

/// Errors from [`AccessRulesClient::delete`](super::AccessRulesClient::delete).
///
/// Deleting decodes nothing and the server refuses it in exactly one way: the rule is not there.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessRuleDeleteError {
    /// The rule named by the request does not exist, or the caller cannot see it.
    #[error("The access rule does not exist")]
    NotFound,
    /// A network or (de)serialization error occurred while calling the server.
    #[error(transparent)]
    Api(ApiError),
}

impl AccessRuleDeleteError {
    /// Maps the server's `404` onto [`NotFound`](Self::NotFound), as the other by-id calls do.
    pub(crate) fn from_by_id_api_error(error: ApiError) -> Self {
        match &error {
            ApiError::Response(content) if content.status == StatusCode::NOT_FOUND => {
                Self::NotFound
            }
            _ => Self::Api(error),
        }
    }
}

impl From<ApiError> for AccessRuleDeleteError {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
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

    fn not_found() -> ApiError {
        ApiError::Response(ResponseContent {
            status: StatusCode::NOT_FOUND,
            message: String::new(),
        })
    }

    #[test]
    fn a_write_failure_becomes_its_own_variant() {
        let error: AccessRuleWriteError = problem("collections_already_governed").into();

        assert!(matches!(
            error,
            AccessRuleWriteError::CollectionsAlreadyGoverned
        ));
    }

    #[test]
    fn a_code_is_read_even_on_a_by_id_call_that_did_not_404() {
        let error = AccessRuleWriteError::from_by_id_api_error(problem("rule_name_taken"));

        assert!(matches!(error, AccessRuleWriteError::NameTaken));
    }

    #[test]
    fn a_by_id_404_still_wins_over_the_code_reader() {
        assert!(matches!(
            AccessRuleWriteError::from_by_id_api_error(not_found()),
            AccessRuleWriteError::NotFound
        ));
        assert!(matches!(
            AccessRuleReadError::from_by_id_api_error(not_found()),
            AccessRuleReadError::NotFound
        ));
        assert!(matches!(
            AccessRuleDeleteError::from_by_id_api_error(not_found()),
            AccessRuleDeleteError::NotFound
        ));
    }

    /// A `404` reached without going through a by-id classifier is not a missing rule - that is the
    /// whole reason the mapping is not on `From<ApiError>`.
    #[test]
    fn an_org_scoped_404_is_not_a_missing_rule() {
        let error: AccessRuleReadError = not_found().into();

        assert!(matches!(error, AccessRuleReadError::Api(_)));
    }

    #[test]
    fn an_unrecognized_code_stays_untyped() {
        let error: AccessRuleWriteError = problem("invented_next_year").into();

        assert!(matches!(error, AccessRuleWriteError::Api(_)));
    }
}
