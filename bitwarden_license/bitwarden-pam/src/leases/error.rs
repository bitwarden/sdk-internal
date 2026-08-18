use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::error::PamDecodeError;

/// Errors returned from [`super::LeasesClient`] operations.
///
/// The lease surface has no local validation and no write-side enum narrowing, so it carries only
/// the decode and transport variants every PAM call can produce. It decodes access-request payloads
/// as well as lease payloads, because [`extend`](super::LeasesClient::extend) returns the updated
/// [`AccessRequestView`](crate::AccessRequestView).
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessLeaseError {
    /// A server response could not be decoded into the requested type.
    #[error(transparent)]
    Decode(#[from] PamDecodeError),
    /// A network or (de)serialization error occurred while calling the server.
    #[error(transparent)]
    Api(#[from] ApiError),
}
