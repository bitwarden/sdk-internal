//! Each write on the requester surface names the failures that one call can produce, rather than
//! every failure the surface can produce. The sets are disjoint and come from the server: one
//! command backs each endpoint and returns an explicit list, so `from_code` below is transcribed
//! from `SubmitAccessRequestCommand`, `ActivateAccessRequestCommand` and
//! `CancelAccessRequestCommand` rather than inferred.
//!
//! Reads use [`PamReadError`](crate::PamReadError) - they have no failure of their own to report.
//!
//! A code this SDK version does not recognize stays `Api` on every one of these, so a server that
//! grows a code never needs a client release to be safe.

use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use super::validate::AccessRequestWindowError;
use crate::{error::PamDecodeError, problem};

/// Errors from [`AccessRequestsClient::request`](super::AccessRequestsClient::request).
///
/// Local validation is reachable only from here - the read paths cannot produce it - which is why
/// this is the only requester error carrying a [`Validation`](Self::Validation) variant.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessRequestSubmitError {
    /// The request failed local validation before being sent to the server.
    #[error(transparent)]
    Validation(#[from] AccessRequestWindowError),

    /// The requester already holds a live lease on this cipher.
    ///
    /// Not a failure to report: the state they asked for already exists. Reconcile - re-read the
    /// access state and let it drive the UI - rather than showing an error.
    #[error("You already have active access to this item")]
    AlreadyActive,
    /// The requester already has a request awaiting a decision. Reconcile, as with
    /// [`AlreadyActive`](Self::AlreadyActive).
    #[error("You already have a pending request for this item")]
    AlreadyPending,
    /// The requester already has an approved request waiting to be activated. Reconcile, as with
    /// [`AlreadyActive`](Self::AlreadyActive).
    #[error("You already have an approved request for this item")]
    AlreadyApproved,

    /// No access rule governs the cipher, so there is nothing to lease.
    #[error("This item does not require a lease")]
    CipherNotGated,
    /// The cipher is approved automatically, so the request must carry a duration - not the window
    /// it carried. Run [`pre_check`](super::AccessRequestsClient::pre_check) first.
    #[error("This item is approved automatically; provide a duration, not a window")]
    DurationExpected,
    /// The cipher needs a human decision, so the request must carry a window - not the duration it
    /// carried. Run [`pre_check`](super::AccessRequestsClient::pre_check) first.
    #[error("This item requires human approval; provide a start and end date, not a duration")]
    WindowExpected,
    /// A duration was expected but was absent, zero or negative.
    #[error("A positive duration is required")]
    DurationMustBePositive,
    /// The requested duration is longer than the governing rule allows. The bound is on
    /// [`AccessPreCheckView`](crate::AccessPreCheckView).
    #[error("The requested duration exceeds the maximum for this item")]
    DurationExceedsMax,
    /// A window was expected but one or both of its ends was absent.
    #[error("A start and end date are required")]
    WindowRequired,
    /// The requested window ends at or before it starts.
    #[error("The start date must be before the end date")]
    WindowEndBeforeStart,
    /// The requested window is longer than the governing rule allows. The bound is on
    /// [`AccessPreCheckView`](crate::AccessPreCheckView).
    #[error("The requested window exceeds the maximum for this item")]
    WindowExceedsMax,
    /// The cipher needs a human decision, and an approver cannot decide without a stated reason.
    #[error("A reason is required for items that need human approval")]
    ReasonRequired,

    /// The governing rule's IP allowlist does not cover the caller's address. A denial, not bad
    /// input: the same request from an allowed network would succeed.
    #[error("Access to this item is not permitted from your current network")]
    DeniedByNetwork,
    /// The governing rule's time window does not cover now. A denial, not bad input: the same
    /// request inside the window would succeed.
    #[error("Access to this item is not permitted at this time")]
    DeniedBySchedule,
    /// The governing rule denied the request for a reason this SDK version does not name.
    #[error("Access to this item is not permitted right now")]
    Denied,

    /// A server response could not be decoded into the requested type.
    #[error(transparent)]
    Decode(#[from] PamDecodeError),
    /// A network or (de)serialization error occurred while calling the server, or the server
    /// refused with a code this SDK version does not recognize.
    #[error(transparent)]
    Api(ApiError),
}

impl AccessRequestSubmitError {
    /// The codes `SubmitAccessRequestCommand` can return.
    fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "access_already_active" => Self::AlreadyActive,
            "access_request_already_pending" => Self::AlreadyPending,
            "access_request_already_approved" => Self::AlreadyApproved,
            "cipher_not_gated" => Self::CipherNotGated,
            "duration_expected" => Self::DurationExpected,
            "window_expected" => Self::WindowExpected,
            "duration_must_be_positive" => Self::DurationMustBePositive,
            "duration_exceeds_max" => Self::DurationExceedsMax,
            "window_required" => Self::WindowRequired,
            "window_end_before_start" => Self::WindowEndBeforeStart,
            "window_exceeds_max" => Self::WindowExceedsMax,
            "reason_required" => Self::ReasonRequired,
            "access_denied_by_network" => Self::DeniedByNetwork,
            "access_denied_by_schedule" => Self::DeniedBySchedule,
            "access_denied" => Self::Denied,
            _ => return None,
        })
    }
}

impl From<ApiError> for AccessRequestSubmitError {
    fn from(error: ApiError) -> Self {
        problem::classify(&error, Self::from_code).unwrap_or(Self::Api(error))
    }
}

/// Errors from [`AccessRequestsClient::activate`](super::AccessRequestsClient::activate).
///
/// Every one of these is about the request's state at the moment activation was attempted, so a
/// caller's usual response is to re-read the request rather than to correct an input.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessRequestActivateError {
    /// The request already minted a lease and that lease has ended. A request authorizes access at
    /// most once, so there is nothing left to activate.
    #[error("This request's access has already been used and is no longer active")]
    LeaseAlreadyUsed,
    /// The request is still waiting on an approver, so there is no approval to activate yet.
    #[error("This request has not been approved yet")]
    NotApproved,
    /// The request has settled into a state activation cannot start from, or lost a race to another
    /// activation that has since ended.
    #[error("This request can no longer be activated")]
    NotActivatable,
    /// The approved window has not opened yet.
    #[error("The approved access window has not started yet")]
    ApprovedWindowNotStarted,
    /// The approved window has closed, so activating it would mint a dead lease.
    #[error("The approved access window has already ended")]
    ApprovedWindowEnded,
    /// The cipher's rule permits one active lease at a time and someone else holds it. Transient -
    /// the same activation succeeds once that lease ends.
    #[error("Another active lease exists for this item")]
    SingleActiveLeaseConflict,

    /// A server response could not be decoded into the requested type.
    #[error(transparent)]
    Decode(#[from] PamDecodeError),
    /// A network or (de)serialization error occurred while calling the server, or the server
    /// refused with a code this SDK version does not recognize.
    #[error(transparent)]
    Api(ApiError),
}

impl AccessRequestActivateError {
    /// The codes `ActivateAccessRequestCommand` can return.
    fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "access_lease_already_used" => Self::LeaseAlreadyUsed,
            "access_request_not_approved" => Self::NotApproved,
            "access_request_not_activatable" => Self::NotActivatable,
            "approved_window_not_started" => Self::ApprovedWindowNotStarted,
            "approved_window_ended" => Self::ApprovedWindowEnded,
            "single_active_lease_conflict" => Self::SingleActiveLeaseConflict,
            _ => return None,
        })
    }
}

impl From<ApiError> for AccessRequestActivateError {
    fn from(error: ApiError) -> Self {
        problem::classify(&error, Self::from_code).unwrap_or(Self::Api(error))
    }
}

/// Errors from [`AccessRequestsClient::cancel`](super::AccessRequestsClient::cancel).
///
/// Cancelling decodes nothing, so unlike its siblings this carries no `Decode` variant.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessRequestCancelError {
    /// The request has already been decided, cancelled or expired, so there is nothing to cancel.
    #[error("This request has already been resolved")]
    AlreadyResolved,
    /// The request has minted a live lease, which now governs the access - end it with
    /// [`LeasesClient::end`](crate::LeasesClient::end) rather than cancelling the request.
    #[error("This request has an active lease; revoke the lease instead")]
    HasActiveLease,

    /// A network or (de)serialization error occurred while calling the server, or the server
    /// refused with a code this SDK version does not recognize.
    #[error(transparent)]
    Api(ApiError),
}

impl AccessRequestCancelError {
    /// The codes `CancelAccessRequestCommand` can return.
    fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "access_request_already_resolved" => Self::AlreadyResolved,
            "access_request_has_active_lease" => Self::HasActiveLease,
            _ => return None,
        })
    }
}

impl From<ApiError> for AccessRequestCancelError {
    fn from(error: ApiError) -> Self {
        problem::classify(&error, Self::from_code).unwrap_or(Self::Api(error))
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::ResponseContent;
    use reqwest::StatusCode;

    use super::*;

    fn problem(status: StatusCode, code: &str) -> ApiError {
        ApiError::Response(ResponseContent {
            status,
            message: format!(r#"{{"errors":{{"code":[{{"type":"{code}"}}]}}}}"#),
        })
    }

    #[test]
    fn a_reconcile_conflict_becomes_its_own_variant() {
        let error: AccessRequestSubmitError =
            problem(StatusCode::CONFLICT, "access_already_active").into();

        assert!(matches!(error, AccessRequestSubmitError::AlreadyActive));
    }

    #[test]
    fn a_field_failure_becomes_its_own_variant() {
        let error: AccessRequestSubmitError =
            problem(StatusCode::BAD_REQUEST, "reason_required").into();

        assert!(matches!(error, AccessRequestSubmitError::ReasonRequired));
    }

    #[test]
    fn an_unrecognized_code_stays_untyped() {
        let error: AccessRequestSubmitError =
            problem(StatusCode::BAD_REQUEST, "invented_next_year").into();

        assert!(matches!(error, AccessRequestSubmitError::Api(_)));
    }

    #[test]
    fn a_transport_failure_stays_untyped() {
        let error: AccessRequestSubmitError = ApiError::Io(std::io::Error::other("reset")).into();

        assert!(matches!(error, AccessRequestSubmitError::Api(_)));
    }

    #[test]
    fn activation_classifies_its_own_codes() {
        let error: AccessRequestActivateError =
            problem(StatusCode::CONFLICT, "single_active_lease_conflict").into();

        assert!(matches!(
            error,
            AccessRequestActivateError::SingleActiveLeaseConflict
        ));
    }

    #[test]
    fn cancellation_classifies_its_own_codes() {
        let error: AccessRequestCancelError =
            problem(StatusCode::CONFLICT, "access_request_has_active_lease").into();

        assert!(matches!(error, AccessRequestCancelError::HasActiveLease));
    }

    /// The split is only worth having if each enum refuses the codes it cannot receive. A submit
    /// code reaching the activate classifier would mean the sets had drifted from the server's.
    #[test]
    fn an_enum_does_not_classify_another_calls_code() {
        let submit_code = problem(StatusCode::CONFLICT, "access_already_active");
        let activate_code = problem(StatusCode::CONFLICT, "approved_window_ended");

        assert!(matches!(
            AccessRequestActivateError::from(submit_code),
            AccessRequestActivateError::Api(_)
        ));
        assert!(matches!(
            AccessRequestSubmitError::from(activate_code),
            AccessRequestSubmitError::Api(_)
        ));
    }
}
