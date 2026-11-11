use bitwarden_crypto::{
    CryptoError,
    safe::{DataEnvelopeError, PasswordProtectedKeyEnvelopeError, SymmetricKeyEnvelopeError},
};

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

    /// The input is not a valid UnsignedSharedKey.
    #[error("Invalid UnsignedSharedKey: {0}")]
    InvalidUnsignedSharedKey(CryptoError),

    /// The input is not a valid LegacyCompatSymmetricKeyEnvelope.
    #[error("Invalid LegacyCompatSymmetricKeyEnvelope: {0}")]
    InvalidLegacyCompatEnvelope(SymmetricKeyEnvelopeError),

    /// The input is not a valid PasswordProtectedKeyEnvelope.
    #[error("Invalid PasswordProtectedKeyEnvelope: {0}")]
    InvalidPasswordProtectedEnvelope(PasswordProtectedKeyEnvelopeError),

    /// The input is not a valid DataEnvelope.
    #[error("Invalid DataEnvelope: {0}")]
    InvalidDataEnvelope(DataEnvelopeError),

    /// The input is not a valid SignedObject.
    #[error("Invalid SignedObject: {0}")]
    InvalidSignedObject(CryptoError),

    /// The input is not a valid SignedPublicKey.
    #[error("Invalid SignedPublicKey: {0}")]
    InvalidSignedPublicKey(CryptoError),

    /// The input is not a valid COSE VerifyingKey.
    #[error("Invalid VerifyingKey: {0}")]
    InvalidVerifyingKey(CryptoError),

    /// The input is not a valid base64 DER SPKI RSA PublicKey.
    #[error("Invalid PublicKey")]
    InvalidPublicKey,

    /// The input is not a valid SignedSecurityState.
    #[error("Invalid SignedSecurityState: {0}")]
    InvalidSignedSecurityState(CryptoError),
}
