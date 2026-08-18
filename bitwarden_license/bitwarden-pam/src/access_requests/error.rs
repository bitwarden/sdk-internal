use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use super::validate::AccessRequestWindowError;
use crate::error::PamDecodeError;

/// Errors returned from [`super::AccessRequestsClient`] operations.
///
/// Local validation is reachable only from
/// [`request`](super::AccessRequestsClient::request) - the read paths cannot produce it - which is
/// why the requester surface carries a `Validation` variant the approver and lease surfaces do not.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessRequestError {
    /// The request failed local validation before being sent to the server.
    #[error(transparent)]
    Validation(#[from] AccessRequestWindowError),
    /// A server response could not be decoded into the requested type.
    #[error(transparent)]
    Decode(#[from] PamDecodeError),
    /// A network or (de)serialization error occurred while calling the server.
    #[error(transparent)]
    Api(#[from] ApiError),
}
