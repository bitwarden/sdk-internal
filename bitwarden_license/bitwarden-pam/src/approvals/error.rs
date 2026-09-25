use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::error::PamDecodeError;

/// Errors returned from [`super::ApprovalsClient`] operations.
///
/// [`UnsubmittableVerdict`](Self::UnsubmittableVerdict) is reachable only from
/// [`decide`](super::ApprovalsClient::decide) - it is the one write path on the approver surface -
/// so no other PAM client exposes it.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum ApprovalError {
    /// A decision was submitted with a verdict this SDK cannot put on the wire.
    /// [`AccessDecisionVerdict::Unknown`](crate::AccessDecisionVerdict::Unknown) is a read-side
    /// spelling for a verdict a newer server returned, never something to submit.
    #[error("An access-request decision cannot be submitted with an unrecognized verdict")]
    UnsubmittableVerdict,
    /// A server response could not be decoded into the requested type.
    #[error(transparent)]
    Decode(#[from] PamDecodeError),
    /// A network or (de)serialization error occurred while calling the server.
    #[error(transparent)]
    Api(#[from] ApiError),
}
