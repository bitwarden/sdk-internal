use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::error::PamDecodeError;

/// Errors returned from [`super::ApprovalsClient`] operations.
///
/// [`UnsubmittableVerdict`](Self::UnsubmittableVerdict) comes only from
/// [`decide`](super::ApprovalsClient::decide).
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum ApprovalError {
    /// A decision was submitted with
    /// [`AccessDecisionVerdict::Unknown`](crate::AccessDecisionVerdict::Unknown), which is
    /// read-only.
    #[error("An access-request decision cannot be submitted with an unrecognized verdict")]
    UnsubmittableVerdict,
    /// A server response could not be decoded into the requested type.
    #[error(transparent)]
    Decode(#[from] PamDecodeError),
    /// A network or (de)serialization error occurred while calling the server.
    #[error(transparent)]
    Api(#[from] ApiError),
}
