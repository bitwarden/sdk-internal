use bitwarden_crypto::{
    CryptoError, EncodingError,
    safe::{DataEnvelopeError, PasswordProtectedKeyEnvelopeError, SymmetricKeyEnvelopeError},
};

/// The single error returned across the server UniFFI boundary.
///
/// The server only needs to know that input was rejected; which parser failed, and why, stays on
/// the Rust side.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum ServerError {
    /// The input is not a valid instance of the requested type.
    #[error("Invalid data")]
    InvalidData,
    /// Two objects in the input name different keys where they must name the same one.
    #[error("Key id mismatch")]
    KeyIdMismatch,
}

/// Maps SDK parse errors to [ServerError::InvalidData], so exports can use `?`.
macro_rules! invalid_data_from {
    ($($error:ty),+ $(,)?) => {
        $(
            impl From<$error> for ServerError {
                fn from(_: $error) -> Self {
                    Self::InvalidData
                }
            }
        )+
    };
}

invalid_data_from!(
    CryptoError,
    EncodingError,
    SymmetricKeyEnvelopeError,
    PasswordProtectedKeyEnvelopeError,
    DataEnvelopeError,
);
