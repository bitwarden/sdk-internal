use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_crypto::CryptoError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use super::validate::RotationValidationError;

/// Errors returned from the PAM rotation clients
/// ([`AccessConnectorsClient`](crate::AccessConnectorsClient),
/// [`TargetSystemsClient`](crate::TargetSystemsClient) and
/// [`RotationConfigsClient`](crate::RotationConfigsClient)).
///
/// The three clients share one error type because they decode the same payloads and fail the same
/// ways: a target system's job history is reachable from a connector and from a config alike, so a
/// malformed job payload fails identically whichever client asked for it.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum RotationError {
    /// The request failed local validation before being sent to the server.
    #[error(transparent)]
    Validation(#[from] RotationValidationError),
    /// The server response was missing a field required to build the requested type.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// A date field in the server response could not be parsed.
    #[error(transparent)]
    Chrono(#[from] chrono::ParseError),
    /// A caller passed an enum variant this SDK models only to describe what a *newer server* may
    /// return - `Unknown` - in a position that has to be written back to the server.
    ///
    /// Distinct from [`Validation`](RotationError::Validation): nothing about the caller's intent
    /// is wrong, the SDK simply cannot name the value on the wire.
    #[error("Cannot send a variant this SDK version does not recognize to the server")]
    UnrecognizedVariant,
    /// The caller is not a member of the organization they addressed, or its key is not in the
    /// key store. Registering a connector hands it the organization key, so it cannot proceed
    /// without one.
    #[error("The organization key is unavailable")]
    MissingOrganizationKey,
    /// A cryptographic operation failed while registering a connector.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A network or (de)serialization error occurred while calling the server.
    #[error(transparent)]
    Api(#[from] ApiError),
}
