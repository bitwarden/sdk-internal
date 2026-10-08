use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_crypto::CryptoError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use super::validate::RotationValidationError;

/// Errors returned from the PAM rotation clients.
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
    /// A caller passed an `Unknown` variant (a value only a newer server returns) in a field sent
    /// back to the server, which the SDK cannot name on the wire.
    #[error("Cannot send a variant this SDK version does not recognize to the server")]
    UnrecognizedVariant,
    /// The caller is not a member of the organization they addressed, or its key is not in the
    /// key store. Registering a connector hands it the organization key, so it needs one.
    #[error("The organization key is unavailable")]
    MissingOrganizationKey,
    /// A cryptographic operation failed while registering a connector.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A network or (de)serialization error occurred while calling the server.
    #[error(transparent)]
    Api(#[from] ApiError),
}
