/// Errors produced by the Keeper crypto layer.
///
/// Messages are intentionally coarse and never include key material, plaintext or ciphertext, so an
/// error can be surfaced to a client or logged without leaking secrets.
#[derive(Debug, thiserror::Error)]
pub enum KeeperCryptoError {
    /// Decryption or authentication failed (bad key, tampered ciphertext, or invalid padding).
    #[error("Keeper decryption failed")]
    Decryption,
    /// A key could not be parsed or has the wrong size.
    #[error("Invalid Keeper key material")]
    InvalidKey,
    /// A private key required to decrypt the given record key type was not supplied.
    /// Currently unreachable (RSA and ECC record-key decryption not yet supported); will be used
    /// when ECC record-key support is added.
    #[error("Missing Keeper private key")]
    MissingPrivateKey,
    /// The input was malformed (too short, wrong length, or not a valid encoding).
    #[error("Malformed Keeper input")]
    InvalidData,
    /// A Keeper `encryptionParams` blob was corrupted or failed its integrity check.
    #[error("Corrupted Keeper encryption parameters")]
    CorruptEncryptionParams,
    /// The record key type is not supported for decryption.
    #[error("Unsupported Keeper record key type")]
    UnsupportedKeyType,
}
