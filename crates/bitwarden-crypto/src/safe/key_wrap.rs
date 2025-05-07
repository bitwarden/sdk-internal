use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{
    error::UnsupportedOperation, CryptoError, EncString, KeyDecryptable, KeyEncryptable,
    SymmetricCryptoKey,
};

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type WrappedSymmetricKey = string;
"#;

/// A wrapped symmetric key is an an [EncString], created where a wrapping key is used to encrypt a
/// key_to_wrap.
///
/// Wrapped keys such as cipher keys, or attachment keys, are used to create a layer of indirection,
/// so that keys can be shared mor granularly, and so that data can be rotated more easily.
#[derive(Clone, PartialEq)]
pub struct WrappedSymmetricKey(EncString);

impl From<EncString> for WrappedSymmetricKey {
    fn from(enc_string: EncString) -> Self {
        WrappedSymmetricKey(enc_string)
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

impl std::fmt::Debug for WrappedSymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappedSymmetricKey")
            .field("inner_enc_string", &self.as_inner())
            .finish()
    }
}

impl schemars::JsonSchema for WrappedSymmetricKey {
    fn schema_name() -> String {
        "WrappedSymmetricKey".to_string()
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        EncString::json_schema(gen)
    }
}

impl WrappedSymmetricKey {
    pub fn into_inner(self) -> EncString {
        self.0
    }

    pub fn as_inner(&self) -> &EncString {
        &self.0
    }

    pub fn try_from_optional(s: Option<String>) -> Result<Option<Self>, CryptoError> {
        EncString::try_from_optional(s).map(|enc_string| enc_string.map(WrappedSymmetricKey))
    }
}

impl FromStr for WrappedSymmetricKey {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        EncString::from_str(s).map(WrappedSymmetricKey)
    }
}

impl WrappedSymmetricKey {
    /// Unwraps a the wrapped symmetric key using the provided wrapping key, returning the contained
    /// wrapped key.
    pub fn unwrap_with(
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
    /// Use this if you have a symmetric crypto key that should protect another symmetric crypto
    /// key.
    pub fn wrap_with(
        &self,
        wrapping_key: &SymmetricCryptoKey,
    ) -> Result<WrappedSymmetricKey, CryptoError> {
        use crate::SymmetricCryptoKey::*;

        // `Aes256CbcHmacKey` can wrap keys by encrypting their byte serialization obtained using
        // `SymmetricCryptoKey::to_encoded()`. `XChaCha20Poly1305Key` need to specify the
        // content format to be either octet stream, in case the wrapped key is a Aes256CbcHmacKey
        // or `Aes256CbcKey`, or by specifying the content format to be CoseKey, in case the
        // wrapped key is a `XChaCha20Poly1305Key`.
        match (wrapping_key, self) {
            (Aes256CbcHmacKey(_), Aes256CbcHmacKey(_) | Aes256CbcKey(_)) => {
                let encoded = self.to_encoded();
                let enc_string = encoded.encrypt_with_key(wrapping_key)?;
                Ok(WrappedSymmetricKey(enc_string))
            }
            _ => Err(CryptoError::OperationNotSupported(
                UnsupportedOperation::EncryptionNotImplementedForKey,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_unwrap() {
        let wrapping_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();

        let wrapped_key = key.wrap_with(&wrapping_key).unwrap();
        let unwrapped_key = wrapped_key.unwrap_with(&wrapping_key).unwrap();

        assert_eq!(key, unwrapped_key);
    }
}
