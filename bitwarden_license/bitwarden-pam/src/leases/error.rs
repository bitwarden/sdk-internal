use bitwarden_core::ApiError;
use bitwarden_crypto::CryptoError;
use bitwarden_error::bitwarden_error;
use bitwarden_vault::VaultParseError;
use thiserror::Error;

use crate::error::PamDecodeError;

/// Errors returned from [`super::LeasesClient`] operations.
///
/// Mostly the decode/transport variants every PAM call can produce, plus the access-request
/// payload from [`extend`](super::LeasesClient::extend). [`VaultParse`](Self::VaultParse) and
/// [`Crypto`](Self::Crypto) come only from [`leased_cipher`](super::LeasesClient::leased_cipher).
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
