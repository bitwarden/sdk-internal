use base64::{engine::general_purpose::STANDARD, Engine};
use bitwarden_crypto::{CoseKeyBytes, CoseSign1Bytes, Pkcs8PrivateKeyBytes, SpkiPublicKeyBytes};

/// A wrapper around a Base64-encoded string that can be used to decode it into a byte vector.
/// This is useful for handling Base64-encoded strings in a type-safe manner,
/// ensuring that the string is always treated as Base64 data.
pub struct Base64String(String);

impl Base64String {
    fn from_vec(val: Vec<u8>) -> Self {
        Base64String(STANDARD.encode(val))
    }
}

impl From<String> for Base64String {
    fn from(val: String) -> Self {
        Base64String(val)
    }
}

impl TryInto<Vec<u8>> for Base64String {
    type Error = base64::DecodeError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        STANDARD.decode(&self.0)
    }
}

impl From<Base64String> for String {
    fn from(val: Base64String) -> Self {
        val.0
    }
}

impl From<Vec<u8>> for Base64String {
    fn from(val: Vec<u8>) -> Self {
        Base64String(STANDARD.encode(val))
    }
}

impl TryInto<SpkiPublicKeyBytes> for Base64String {
    type Error = base64::DecodeError;

    fn try_into(self) -> Result<SpkiPublicKeyBytes, Self::Error> {
        let bytes: Vec<u8> = self.try_into()?;
        Ok(SpkiPublicKeyBytes::from(bytes))
    }
}

impl TryInto<Pkcs8PrivateKeyBytes> for Base64String {
    type Error = base64::DecodeError;

    fn try_into(self) -> Result<Pkcs8PrivateKeyBytes, Self::Error> {
        let bytes: Vec<u8> = self.try_into()?;
        Ok(Pkcs8PrivateKeyBytes::from(bytes))
    }
}

impl From<Pkcs8PrivateKeyBytes> for Base64String {
    fn from(val: Pkcs8PrivateKeyBytes) -> Self {
        Self::from_vec(val.to_vec())
    }
}

impl From<CoseKeyBytes> for Base64String {
    fn from(val: CoseKeyBytes) -> Self {
        Self::from_vec(val.to_vec())
    }
}

impl From<SpkiPublicKeyBytes> for Base64String {
    fn from(val: SpkiPublicKeyBytes) -> Self {
        Self::from_vec(val.to_vec())
    }
}

impl From<CoseSign1Bytes> for Base64String {
    fn from(val: CoseSign1Bytes) -> Self {
        Self::from_vec(val.to_vec())
    }
}
