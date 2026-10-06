use bitwarden_core::ApiError;
use bitwarden_crypto::CryptoError;
use bitwarden_error::bitwarden_error;
use bitwarden_vault::VaultParseError;
use thiserror::Error;

use crate::error::PamDecodeError;

/// Errors returned from [`super::LeasesClient`] operations.
///
/// The lease surface has no local validation and no write-side enum narrowing, so it mostly carries
/// the decode and transport variants every PAM call can produce. It decodes access-request payloads
/// as well as lease payloads, because [`extend`](super::LeasesClient::extend) returns the updated
/// [`AccessRequestView`](crate::AccessRequestView).
///
/// [`VaultParse`](Self::VaultParse) and [`Crypto`](Self::Crypto) are reachable only from
/// [`leased_cipher`](super::LeasesClient::leased_cipher), the one call that reads a vault payload
/// rather than a leasing one.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessLeaseError {
    /// A server response could not be decoded into the requested type.
    #[error(transparent)]
    Decode(#[from] PamDecodeError),
    /// A cipher payload could not be parsed into the SDK's vault model.
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    /// A leased cipher could not be decrypted.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A network or (de)serialization error occurred while calling the server.
    #[error(transparent)]
    Api(#[from] ApiError),
}
