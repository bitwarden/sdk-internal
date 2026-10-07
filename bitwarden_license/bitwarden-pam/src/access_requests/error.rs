use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use super::validate::AccessRequestWindowError;
use crate::error::PamDecodeError;

/// Errors returned from [`super::AccessRequestsClient`] operations.
///
/// [`Validation`](Self::Validation) comes only from
/// [`request`](super::AccessRequestsClient::request).
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
