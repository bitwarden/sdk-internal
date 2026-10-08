use bitwarden_error::bitwarden_error;
use thiserror::Error;

/// Errors returned by [`AgentFillApprovalClient`](crate::AgentFillApprovalClient).
///
/// The desktop app treats every `verify_response` error as a denial, except
/// [`Expired`](Self::Expired), which it reports as an expired request.
#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum AgentFillApprovalError {
    /// The payload could not be sealed, for example because the user key isn't loaded.
    #[error("Failed to seal the approval payload")]
    Seal,
    /// The payload could not be opened: wrong key, wrong namespace or unsupported format.
    #[error("Failed to open the approval payload")]
    Unseal,
    /// The response answers a different approval request.
    #[error("The response answers a different approval request")]
    RequestIdMismatch,
    /// The response doesn't echo the pending request's challenge.
    #[error("The response challenge doesn't match the pending request")]
    ChallengeMismatch,
    /// The response's expiry has passed.
    #[error("The response has expired")]
    Expired,
    /// The decision is malformed: an approval without a cipher ID, or a denial with one.
    #[error("The response decision is invalid")]
    InvalidDecision,
}
