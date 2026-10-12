use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_crypto::CryptoError;
use bitwarden_error::bitwarden_error;
use bitwarden_pam_sealed::SealedDataError;
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
    /// key store. Registering a connector, or sealing a target system or rotation config, needs
    /// the organization key.
    #[error("The organization key is unavailable")]
    MissingOrganizationKey,
    /// A cryptographic operation failed while registering a connector.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Sealing a target system or rotation config blob failed before it was sent to the server.
    /// Unsealing failures don't raise this: they degrade the item's sealed fields to `None`
    /// instead, so one bad item cannot fail a `list`.
    #[error(transparent)]
    Sealed(#[from] SealedDataError),
    /// A rotation config named a `target_system_id` that does not exist in this organization.
    #[error("Target system not found")]
    TargetSystemNotFound,
    /// A network or (de)serialization error occurred while calling the server.
    #[error(transparent)]
    Api(#[from] ApiError),
}
