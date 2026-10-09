use bitwarden_crypto::CryptoError;
use thiserror::Error;

/// Errors from minting or opening an access token's key material.
#[derive(Debug, Error)]
pub enum AccessTokenError {
    /// The encrypted payload could not be decoded or decrypted. Carries no payload content.
    #[error("payload is invalid")]
    InvalidPayload,
    /// The decrypted payload did not contain a valid organization key.
    #[error("payload does not contain a valid encryption key")]
    InvalidOrgKey,
    /// A cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}
