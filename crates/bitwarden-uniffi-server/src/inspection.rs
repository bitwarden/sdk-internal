use bitwarden_crypto::{EncString, KeyId, SymmetricKeyAlgorithm, UnsignedSharedKey};

use crate::ServerError;

/// The key ids a crypto object names, each as 32 lowercase hex characters.
///
/// Read from headers only: nothing is decrypted or verified, so the server must not trust them
/// beyond routing and consistency checks.
#[derive(uniffi::Record, Debug, Default, PartialEq)]
pub struct CryptoObjectKeyIds {
    /// The key this object holds (envelopes) or is (verifying keys), if it names one.
    pub contained_key_id: Option<String>,
    /// The key this object is encrypted or sealed with, if it names one.
    pub encrypted_by_key_id: Option<String>,
    /// The key that signed this object, if it is signed.
    pub signed_by_key_id: Option<String>,
}

/// The symmetric algorithm an EncString is encrypted with.
#[derive(uniffi::Enum, Debug, PartialEq)]
pub enum EncStringAlgorithm {
    /// Type 0. Unauthenticated legacy AES-256-CBC.
    Aes256Cbc,
    /// Type 2, or type 7 sealed with a type 2 key.
    Aes256CbcHmac,
    /// Type 7.
    Aes256Gcm,
    /// Type 7.
    XAes256Gcm,
    /// Type 7.
    XChaCha20Poly1305,
}

impl From<SymmetricKeyAlgorithm> for EncStringAlgorithm {
    fn from(algorithm: SymmetricKeyAlgorithm) -> Self {
        match algorithm {
            SymmetricKeyAlgorithm::Aes256CbcHmac => Self::Aes256CbcHmac,
            SymmetricKeyAlgorithm::Aes256Gcm => Self::Aes256Gcm,
            SymmetricKeyAlgorithm::XAes256Gcm => Self::XAes256Gcm,
            SymmetricKeyAlgorithm::XChaCha20Poly1305 => Self::XChaCha20Poly1305,
        }
    }
}

/// What a symmetric EncString (type 0, 2 or 7) carries.
#[derive(uniffi::Record, Debug, PartialEq)]
pub struct EncStringInfo {
    /// The algorithm it is encrypted with. For type 7, read from the COSE header.
    pub algorithm: EncStringAlgorithm,
    /// The id of the encrypting key. Only COSE EncStrings (type 7) carry one.
    pub encrypted_by_key_id: Option<String>,
}

impl TryFrom<&EncString> for EncStringInfo {
    type Error = ServerError;

    fn try_from(enc_string: &EncString) -> Result<Self, ServerError> {
        // The SDK reports no algorithm for type 0, which carries no MAC, nor for an unknown COSE
        // algorithm, which is rejected.
        let algorithm = match enc_string {
            EncString::Aes256Cbc_B64 { .. } => EncStringAlgorithm::Aes256Cbc,
            _ => enc_string
                .algorithm()
                .map(EncStringAlgorithm::from)
                .ok_or(ServerError::InvalidData)?,
        };

        Ok(Self {
            algorithm,
            encrypted_by_key_id: hex(enc_string.key_id()),
        })
    }
}

/// The public-key algorithm an UnsignedSharedKey is encrypted with.
#[derive(uniffi::Enum, Debug, PartialEq)]
pub enum UnsignedSharedKeyAlgorithm {
    /// Type 3.
    Rsa2048OaepSha256,
    /// Type 4.
    Rsa2048OaepSha1,
    /// Type 5. Deprecated.
    Rsa2048OaepSha256HmacSha256,
    /// Type 6. Deprecated.
    Rsa2048OaepSha1HmacSha256,
}

/// What an RSA-encrypted UnsignedSharedKey (type 3 to 6) carries. It names no key.
#[derive(uniffi::Record, Debug, PartialEq)]
pub struct UnsignedSharedKeyInfo {
    /// The public-key algorithm it is encrypted with.
    pub algorithm: UnsignedSharedKeyAlgorithm,
}

impl From<&UnsignedSharedKey> for UnsignedSharedKeyInfo {
    // Types 5 and 6 are deprecated in the SDK but still parse, so they are still reported.
    #[allow(deprecated)]
    fn from(shared_key: &UnsignedSharedKey) -> Self {
        let algorithm = match shared_key {
            UnsignedSharedKey::Rsa2048_OaepSha256_B64 { .. } => {
                UnsignedSharedKeyAlgorithm::Rsa2048OaepSha256
            }
            UnsignedSharedKey::Rsa2048_OaepSha1_B64 { .. } => {
                UnsignedSharedKeyAlgorithm::Rsa2048OaepSha1
            }
            UnsignedSharedKey::Rsa2048_OaepSha256_HmacSha256_B64 { .. } => {
                UnsignedSharedKeyAlgorithm::Rsa2048OaepSha256HmacSha256
            }
            UnsignedSharedKey::Rsa2048_OaepSha1_HmacSha256_B64 { .. } => {
                UnsignedSharedKeyAlgorithm::Rsa2048OaepSha1HmacSha256
            }
        };

        Self { algorithm }
    }
}

/// Formats a key id as 32 lowercase hex characters.
pub(crate) fn hex(key_id: Option<KeyId>) -> Option<String> {
    key_id.map(|id| id.to_string())
}
