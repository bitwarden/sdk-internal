use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};

use crate::{CryptoError, EncString, KeyDecryptable, KeyEncryptable, SymmetricCryptoKey};

#[derive(Clone, PartialEq)]
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
    /// Unwraps a the wrapped symmetric key using the provided wrapping key, returning the contained wrapped key.
    pub fn unwrap(
        &self,
        wrapping_key: &SymmetricCryptoKey,
    ) -> Result<SymmetricCryptoKey, CryptoError> {
        let decrypted_bytes: Vec<u8> = self.0.decrypt_with_key(wrapping_key)?;
        SymmetricCryptoKey::try_from(decrypted_bytes)
    }
}

impl SymmetricCryptoKey {
    /// Wraps (encrypts) the key using the provided wrapping key.
    /// 
    /// Use this if you have a symmetric crypto key that should protect another symmetric crypto key.
    pub fn wrap(
        &self,
        wrapping_key: &SymmetricCryptoKey,
    ) -> Result<WrappedSymmetricKey, CryptoError> {
        let encoded = self.to_vec();
        let enc_string = encoded.encrypt_with_key(wrapping_key)?;
        Ok(enc_string.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_unwrap() {
        let mut rng = rand::thread_rng();
        let wrapping_key = SymmetricCryptoKey::generate(&mut rng);
        let key = SymmetricCryptoKey::generate(&mut rng);

        let wrapped_key = key.wrap(&wrapping_key).unwrap();
        let unwrapped_key = wrapped_key.unwrap(&wrapping_key).unwrap();

        assert_eq!(key, unwrapped_key);
    }
}