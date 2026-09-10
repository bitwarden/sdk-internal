use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_crypto::CryptoError;
use bitwarden_error::bitwarden_error;
use bitwarden_organization_crypto::invite::InviteKeyBundleError;
use thiserror::Error;

/// Errors returned from invite link client operations.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum InviteLinkError {
    /// A cryptographic invite operation (creating, unsealing, or recovering the invite) failed.
    #[error(transparent)]
    Invite(#[from] InviteKeyBundleError),
    /// A network request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A low-level cryptographic operation (key wrapping, encapsulation, or public-key parsing)
    /// failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A required field was missing from a server response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// A value was present but malformed and could not be parsed.
    #[error("Failed to parse `{0}`")]
    ParseFailure(&'static str),
    /// The account-recovery public key returned by the server does not match the organization
    /// public key bound into the invite.
    #[error("Account recovery public key does not match the invite's bound organization key")]
    RecoveryKeyMismatch,
    /// No allowed domains were specified.
    #[error("At least one allowed domain is required.")]
    NoAllowedDomains,
}
