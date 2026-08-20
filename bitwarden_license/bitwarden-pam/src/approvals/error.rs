use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::{error::PamDecodeError, problem};

/// Errors returned from [`super::ApprovalsClient`] operations.
///
/// [`UnsubmittableVerdict`](Self::UnsubmittableVerdict) is reachable only from
/// [`decide`](super::ApprovalsClient::decide) - it is the one write path on the approver surface -
/// so no other PAM client exposes it. The same is true of the three named server failures below,
/// which each correspond to one stable code in the server's problem response; a code this SDK
/// version does not recognize stays [`Api`](Self::Api).
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum ApprovalError {
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

impl ApprovalError {
    /// The server's codes, in the order the approver surface can produce them.
    fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "access_request_already_resolved" => Self::AlreadyResolved,
            "cannot_decide_own_request" => Self::CannotDecideOwnRequest,
            "requested_window_ended" => Self::RequestedWindowEnded,
            _ => return None,
        })
    }
}

/// Classifies every failed call on this surface, so a caller gets the typed variant whichever
/// method it came from.
impl From<ApiError> for ApprovalError {
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
        let error: ApprovalError = problem("access_request_already_resolved").into();

        assert!(matches!(error, ApprovalError::AlreadyResolved));
    }

    #[test]
    fn a_self_approval_becomes_its_own_variant() {
        let error: ApprovalError = problem("cannot_decide_own_request").into();

        assert!(matches!(error, ApprovalError::CannotDecideOwnRequest));
    }

    #[test]
    fn an_unrecognized_code_stays_untyped() {
        let error: ApprovalError = problem("invented_next_year").into();

        assert!(matches!(error, ApprovalError::Api(_)));
    }
}
