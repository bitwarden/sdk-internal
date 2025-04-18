use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};

use crate::{CryptoError, EncString, KeyDecryptable, KeyEncryptable, SymmetricCryptoKey};

pub struct WrappedSymmetricKey(EncString);

impl Debug for WrappedSymmetricKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for WrappedSymmetricKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WrappedSymmetricKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        EncString::deserialize(deserializer).map(WrappedSymmetricKey)
    }
}

impl From<EncString> for WrappedSymmetricKey {
    fn from(enc_string: EncString) -> Self {
        WrappedSymmetricKey(enc_string)
    }
}

impl AsRef<EncString> for WrappedSymmetricKey {
    fn as_ref(&self) -> &EncString {
        &self.0
    }
}

impl From<WrappedSymmetricKey> for EncString {
    fn from(wrapped: WrappedSymmetricKey) -> Self {
        wrapped.0
    }
}

impl WrappedSymmetricKey {
    pub fn unwrap(
        &self,
        wrapping_key: &SymmetricCryptoKey,
    ) -> Result<SymmetricCryptoKey, CryptoError> {
        let decrypted_bytes: Vec<u8> = (&self.0).decrypt_with_key(wrapping_key)?;
        Ok(SymmetricCryptoKey::try_from(decrypted_bytes)?)
    }
}

impl SymmetricCryptoKey {
    pub fn wrap(
        &self,
        wrapping_key: &SymmetricCryptoKey,
    ) -> Result<WrappedSymmetricKey, CryptoError> {
        let encoded = self.to_vec();
        let enc_string = encoded.encrypt_with_key(wrapping_key)?;
        Ok(enc_string.into())
    }
}
