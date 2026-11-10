use bitwarden_crypto::{CryptoError, safe::SymmetricKeyEnvelopeError};

/// Errors returned across the server UniFFI boundary.
///
/// Flat, so C# receives one exception type per variant carrying the display message. The inner
/// errors are not UniFFI types.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum ServerError {
    /// The input is not a valid EncString.
    #[error("Invalid EncString: {0}")]
    InvalidEncString(CryptoError),

    /// The input is not a valid SymmetricKeyEnvelope.
    #[error("Invalid SymmetricKeyEnvelope: {0}")]
    InvalidEnvelope(SymmetricKeyEnvelopeError),
}
