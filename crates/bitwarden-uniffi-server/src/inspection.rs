use bitwarden_crypto::{
    EncString, PublicKey, PublicKeyEncryptionAlgorithm, SignatureAlgorithm, SymmetricKeyAlgorithm,
    UnsignedSharedKey, VerifyingKey,
};

use crate::ServerError;

/// The key ids a crypto object names, each as 32 lowercase hex characters.
#[derive(uniffi::Record, Debug, Default, PartialEq)]
pub struct CryptoObjectKeyIds {
    /// The key this object holds or is, if it names one.
    pub contained_key_id: Option<String>,
    /// The key this object is encrypted or sealed with, if it names one.
    pub encrypted_by_key_id: Option<String>,
    /// The key that signed this object, if it is signed.
    pub signed_by_key_id: Option<String>,
}

/// The symmetric algorithm an EncString is encrypted with.
#[derive(uniffi::Enum, Debug, PartialEq)]
pub enum EncStringAlgorithm {
    /// AES-256-CBC.
    Aes256Cbc,
    /// AES-256-CBC with HMAC-SHA256.
    Aes256CbcHmac,
    /// AES-256-GCM.
    Aes256Gcm,
    /// XAES-256-GCM.
    XAes256Gcm,
    /// XChaCha20-Poly1305.
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

/// What an EncString carries.
#[derive(uniffi::Record, Debug, PartialEq)]
pub struct EncStringInfo {
    /// The algorithm it is encrypted with.
    pub algorithm: EncStringAlgorithm,
    /// The id of the encrypting key, if it names one.
    pub encrypted_by_key_id: Option<String>,
}

impl TryFrom<&EncString> for EncStringInfo {
    type Error = ServerError;

    fn try_from(enc_string: &EncString) -> Result<Self, ServerError> {
        let algorithm = match enc_string {
            // `algorithm()` returns a key algorithm, and no key is AES-256-CBC without HMAC.
            EncString::Aes256Cbc_B64 { .. } => EncStringAlgorithm::Aes256Cbc,
            _ => enc_string
                .algorithm()
                .ok_or(ServerError::InvalidData)?
                .into(),
        };

        Ok(Self {
            algorithm,
            encrypted_by_key_id: enc_string.key_id().map(|id| id.to_string()),
        })
    }
}

/// The public-key algorithm an UnsignedSharedKey is encrypted with.
#[derive(uniffi::Enum, Debug, PartialEq)]
pub enum UnsignedSharedKeyAlgorithm {
    /// RSA-2048 OAEP with SHA-256.
    Rsa2048OaepSha256,
    /// RSA-2048 OAEP with SHA-1.
    Rsa2048OaepSha1,
    /// RSA-2048 OAEP with SHA-256, plus HMAC-SHA256.
    Rsa2048OaepSha256HmacSha256,
    /// RSA-2048 OAEP with SHA-1, plus HMAC-SHA256.
    Rsa2048OaepSha1HmacSha256,
}

/// What an UnsignedSharedKey carries.
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

/// The signature algorithm of a VerifyingKey.
#[derive(uniffi::Enum, Debug, PartialEq)]
pub enum VerifyingKeyAlgorithm {
    /// Ed25519.
    Ed25519,
    /// ML-DSA-44.
    MlDsa44,
}

/// What a VerifyingKey carries.
#[derive(uniffi::Record, Debug, PartialEq)]
pub struct VerifyingKeyInfo {
    /// The signature algorithm.
    pub algorithm: VerifyingKeyAlgorithm,
    /// The key id, as 32 lowercase hex characters.
    pub key_id: String,
}

impl From<&VerifyingKey> for VerifyingKeyInfo {
    fn from(key: &VerifyingKey) -> Self {
        let algorithm = match key.algorithm() {
            SignatureAlgorithm::Ed25519 => VerifyingKeyAlgorithm::Ed25519,
            SignatureAlgorithm::MlDsa44 => VerifyingKeyAlgorithm::MlDsa44,
        };

        Self {
            algorithm,
            key_id: key.key_id().to_string(),
        }
    }
}

/// The encryption algorithm of a PublicKey.
#[derive(uniffi::Enum, Debug, PartialEq)]
pub enum PublicKeyAlgorithm {
    /// RSA OAEP with SHA-1.
    RsaOaepSha1,
}

/// What a PublicKey carries.
#[derive(uniffi::Record, Debug, PartialEq)]
pub struct PublicKeyInfo {
    /// The encryption algorithm.
    pub algorithm: PublicKeyAlgorithm,
    /// The key id, as 32 lowercase hex characters.
    pub key_id: String,
}

impl TryFrom<&PublicKey> for PublicKeyInfo {
    type Error = ServerError;

    fn try_from(key: &PublicKey) -> Result<Self, ServerError> {
        let algorithm = match key.algorithm() {
            PublicKeyEncryptionAlgorithm::RsaOaepSha1 => PublicKeyAlgorithm::RsaOaepSha1,
        };

        Ok(Self {
            algorithm,
            key_id: key.key_id()?.to_string(),
        })
    }
}
