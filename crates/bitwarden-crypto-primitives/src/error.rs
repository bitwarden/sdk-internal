/// Error returned by every fallible primitive. Carries no secret data.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// The key bytes do not encode a valid key.
    #[error("Invalid key")]
    InvalidKey,
    /// A length, parameter set, or other input is out of range.
    #[error("Invalid parameters")]
    InvalidParameters,
    /// Decryption or authentication failed.
    #[error("Decryption failed")]
    DecryptionFailed,
    /// The signature or MAC does not verify.
    #[error("Invalid signature")]
    InvalidSignature,
}
