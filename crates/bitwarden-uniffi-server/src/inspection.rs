use bitwarden_crypto::{CryptoError, EncString, KeyId, UnsignedSharedKey};

// Type prefixes of the `<type>.<payload>` wire format. EncStrings (symmetric) use 0, 2 and 7;
// UnsignedSharedKeys (RSA) use 3 to 6.
const AES256_CBC: u8 = 0;
const AES256_CBC_HMAC_SHA256: u8 = 2;
const RSA2048_OAEP_SHA256: u8 = 3;
const RSA2048_OAEP_SHA1: u8 = 4;
const RSA2048_OAEP_SHA256_HMAC_SHA256: u8 = 5;
const RSA2048_OAEP_SHA1_HMAC_SHA256: u8 = 6;
const COSE_ENCRYPT0: u8 = 7;

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

/// What a symmetric EncString (type 0, 2 or 7) carries.
#[derive(uniffi::Record, Debug, PartialEq)]
pub struct EncStringInfo {
    /// The numeric type prefix, e.g. `2` for an AES-CBC-HMAC EncString (`2.iv|data|mac`).
    pub encryption_type: u8,
    /// The id of the encrypting key. Only COSE EncStrings (type 7) carry one.
    pub encrypted_by_key_id: Option<String>,
}

/// What an RSA-encrypted UnsignedSharedKey (type 3 to 6) carries. It names no key.
#[derive(uniffi::Record, Debug, PartialEq)]
pub struct UnsignedSharedKeyInfo {
    /// The numeric type prefix, e.g. `4` for RSA-OAEP-SHA1 (`4.data`).
    pub encryption_type: u8,
}

impl TryFrom<&EncString> for EncStringInfo {
    type Error = CryptoError;

    fn try_from(enc_string: &EncString) -> Result<Self, CryptoError> {
        let encryption_type = match enc_string {
            EncString::Aes256Cbc_B64 { .. } => AES256_CBC,
            EncString::Aes256Cbc_HmacSha256_B64 { .. } => AES256_CBC_HMAC_SHA256,
            EncString::Cose_Encrypt0_B64 { .. } => COSE_ENCRYPT0,
            EncString::Unparseable { .. } => return Err(CryptoError::UnparseableEncString),
        };

        Ok(Self {
            encryption_type,
            encrypted_by_key_id: hex(enc_string.key_id()),
        })
    }
}

impl From<&UnsignedSharedKey> for UnsignedSharedKeyInfo {
    #[allow(deprecated)]
    fn from(shared_key: &UnsignedSharedKey) -> Self {
        let encryption_type = match shared_key {
            UnsignedSharedKey::Rsa2048_OaepSha256_B64 { .. } => RSA2048_OAEP_SHA256,
            UnsignedSharedKey::Rsa2048_OaepSha1_B64 { .. } => RSA2048_OAEP_SHA1,
            UnsignedSharedKey::Rsa2048_OaepSha256_HmacSha256_B64 { .. } => {
                RSA2048_OAEP_SHA256_HMAC_SHA256
            }
            UnsignedSharedKey::Rsa2048_OaepSha1_HmacSha256_B64 { .. } => {
                RSA2048_OAEP_SHA1_HMAC_SHA256
            }
        };

        Self { encryption_type }
    }
}

/// Formats a key id as 32 lowercase hex characters.
pub(crate) fn hex(key_id: Option<KeyId>) -> Option<String> {
    key_id.map(|id| id.to_string())
}
