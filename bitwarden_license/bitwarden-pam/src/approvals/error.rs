use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::{error::PamDecodeError, problem};

/// Errors from [`ApprovalsClient::decide`](super::ApprovalsClient::decide), the one write path on
/// the approver surface.
///
/// The reads use [`PamReadError`](crate::PamReadError). The three named server failures are the
/// codes `DecideAccessRequestCommand` can return; a code this SDK version does not recognize stays
/// [`Api`](Self::Api).
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessDecisionError {
    /// A decision was submitted with a verdict this SDK cannot put on the wire.
    /// [`AccessDecisionVerdict::Unknown`](crate::AccessDecisionVerdict::Unknown) is a read-side
    /// spelling for a verdict a newer server returned, never something to submit.
    #[error("An access-request decision cannot be submitted with an unrecognized verdict")]
    UnsubmittableVerdict,
    /// The request has already been decided, cancelled or expired, so there is no decision to
    /// take. Whichever approver arrives second finds it settled.
    #[error("This request has already been resolved")]
    AlreadyResolved,
    /// The caller is the request's own requester. Self-approval is refused server-side even though
    /// an approver surface should not offer it.
    #[error("You cannot decide your own request")]
    CannotDecideOwnRequest,
    /// The window the requester asked for has already closed, so approving it would mint an
    /// approval that can never be activated. Denying it is still allowed.
    #[error("The requested access window has already ended")]
    RequestedWindowEnded,

    /// A server response could not be decoded into the requested type.
    #[error(transparent)]
    Decode(#[from] PamDecodeError),
    /// A network or (de)serialization error occurred while calling the server, or the server
    /// refused with a code this SDK version does not recognize.
    #[error(transparent)]
    Api(ApiError),
}

impl AccessDecisionError {
    /// The codes `DecideAccessRequestCommand` can return.
    fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "access_request_already_resolved" => Self::AlreadyResolved,
            "cannot_decide_own_request" => Self::CannotDecideOwnRequest,
            "requested_window_ended" => Self::RequestedWindowEnded,
            _ => return None,
        })
    }
}

impl From<ApiError> for AccessDecisionError {
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
    fn a_settled_request_becomes_its_own_variant() {
        let error: AccessDecisionError = problem("access_request_already_resolved").into();

        assert!(matches!(error, AccessDecisionError::AlreadyResolved));
    }

    #[test]
    fn a_self_approval_becomes_its_own_variant() {
        let error: AccessDecisionError = problem("cannot_decide_own_request").into();

        assert!(matches!(error, AccessDecisionError::CannotDecideOwnRequest));
    }

    #[test]
    fn an_unrecognized_code_stays_untyped() {
        let error: AccessDecisionError = problem("invented_next_year").into();

        assert!(matches!(error, AccessDecisionError::Api(_)));
    }
}
