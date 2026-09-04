use std::str::FromStr;

use bitwarden_encoding::FromStrVisitor;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::{FromWasmAbi, IntoWasmAbi, OptionFromWasmAbi};
use zeroize::Zeroize;

use crate::{CryptoError, error::EncodingError};

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type KeyId = Tagged<string, "KeyId">;
"#;

/// Since `KeyId` is a wrapper around UUIDs, this is statically 16 bytes.
pub(crate) const KEY_ID_SIZE: usize = 16;

/// A key id is a unique identifier for a single key. There is a 1:1 mapping between key ID and key
/// bytes, so something like a user key rotation is replacing the key with ID A with a new key with
/// ID B.
#[derive(Clone, PartialEq, Zeroize)]
pub struct KeyId([u8; KEY_ID_SIZE]);

// Constant time here is not implemented because the key-id itself is secret, it is not.
// Instead, it is implemented to correctly allow other things that implement ct_eq to correctly
// implement the ct_eq contract. This is the case for COSE keys that have key material and a key id.
impl ConstantTimeEq for KeyId {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Fixed length identifiers for keys.
/// These are intended to be unique and constant per-key.
///
/// Currently these are randomly generated 16 byte identifiers, which is considered safe to randomly
/// generate with vanishingly small collision chance. However, the generation of IDs is an internal
/// concern and may change in the future.
impl KeyId {
    /// Creates a new random key ID randomly, sampled from the crates CSPRNG.
    pub fn make() -> Self {
        let mut rng = bitwarden_random::rng();
        let mut key_id = [0u8; KEY_ID_SIZE];
        rng.fill(&mut key_id);
        Self(key_id)
    }

    /// Returns the key ID as a slice of bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for KeyId {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != KEY_ID_SIZE {
            return Err("Invalid length for KeyId");
        }
        let mut key_id = [0u8; KEY_ID_SIZE];
        key_id.copy_from_slice(value);
        Ok(Self(key_id))
    }
}

impl From<KeyId> for [u8; KEY_ID_SIZE] {
    fn from(key_id: KeyId) -> Self {
        key_id.0
    }
}

impl From<&KeyId> for Vec<u8> {
    fn from(key_id: &KeyId) -> Self {
        key_id.0.as_slice().to_vec()
    }
}

impl From<[u8; KEY_ID_SIZE]> for KeyId {
    fn from(bytes: [u8; KEY_ID_SIZE]) -> Self {
        Self(bytes)
    }
}

/// Key ids travel on the wire as a lowercase hex encoding of the 16 raw bytes, giving a fixed
/// 32-character string. The server rejects any other encoding.
impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Parses the hex encoding produced by [`Display`](std::fmt::Display). Anything that is not exactly
/// 16 bytes worth of hex is rejected.
impl FromStr for KeyId {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| EncodingError::InvalidValue("key id"))?;
        Self::try_from(bytes.as_slice()).map_err(|_| EncodingError::InvalidValue("key id").into())
    }
}

impl Serialize for KeyId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

// Key ids cross the WASM boundary as their hex string form, mirroring the other crypto types.
#[cfg(feature = "wasm")]
bitwarden_ffi::impl_wire_object!(KeyId);

#[cfg(feature = "wasm")]
impl wasm_bindgen::describe::WasmDescribe for KeyId {
    fn describe() {
        <String as wasm_bindgen::describe::WasmDescribe>::describe();
    }
}

#[cfg(feature = "wasm")]
impl FromWasmAbi for KeyId {
    type Abi = <String as FromWasmAbi>::Abi;

    unsafe fn from_abi(abi: Self::Abi) -> Self {
        use wasm_bindgen::UnwrapThrowExt;

        let s = unsafe { String::from_abi(abi) };
        Self::from_str(&s).unwrap_throw()
    }
}

#[cfg(feature = "wasm")]
impl OptionFromWasmAbi for KeyId {
    fn is_none(abi: &Self::Abi) -> bool {
        <String as OptionFromWasmAbi>::is_none(abi)
    }
}

#[cfg(feature = "wasm")]
impl IntoWasmAbi for KeyId {
    type Abi = <String as IntoWasmAbi>::Abi;

    fn into_abi(self) -> Self::Abi {
        self.to_string().into_abi()
    }
}

#[cfg(feature = "wasm")]
impl TryFrom<wasm_bindgen::JsValue> for KeyId {
    type Error = CryptoError;

    fn try_from(value: wasm_bindgen::JsValue) -> Result<Self, Self::Error> {
        let string = value
            .as_string()
            .ok_or(EncodingError::InvalidValue("key id"))?;
        Self::from_str(&string)
    }
}

impl std::fmt::Debug for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyId({})", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "Manual test to verify debug format"]
    fn test_key_id_debug() {
        let key_id = KeyId::make();
        println!("{:?}", key_id);
    }

    const TEST_KEY_ID_HEX: &str = "000102030405060708090a0b0c0d0e0f";

    fn test_key_id() -> KeyId {
        KeyId::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    }

    #[test]
    fn test_from_str_roundtrips_display() {
        let key_id = KeyId::make();

        assert_eq!(KeyId::from_str(&key_id.to_string()).unwrap(), key_id);
    }

    #[test]
    fn test_from_str_parses_lowercase_hex() {
        assert_eq!(KeyId::from_str(TEST_KEY_ID_HEX).unwrap(), test_key_id());
    }

    #[test]
    fn test_from_str_rejects_non_hex() {
        assert!(KeyId::from_str("not a key id at all, no sir").is_err());
    }

    #[test]
    fn test_from_str_rejects_odd_length() {
        assert!(KeyId::from_str("000102030405060708090a0b0c0d0e0").is_err());
    }

    #[test]
    fn test_from_str_rejects_wrong_byte_length() {
        // Valid hex, but 15 and 17 bytes rather than the required 16.
        assert!(KeyId::from_str("000102030405060708090a0b0c0d0e").is_err());
        assert!(KeyId::from_str("000102030405060708090a0b0c0d0e0f10").is_err());
    }

    #[test]
    fn test_serde_serializes_to_hex_string() {
        assert_eq!(
            serde_json::to_string(&test_key_id()).unwrap(),
            format!("\"{TEST_KEY_ID_HEX}\"")
        );
    }

    #[test]
    fn test_serde_roundtrip() {
        let key_id = KeyId::make();
        let json = serde_json::to_string(&key_id).unwrap();

        assert_eq!(serde_json::from_str::<KeyId>(&json).unwrap(), key_id);
    }

    #[test]
    fn test_serde_rejects_malformed_hex() {
        assert!(serde_json::from_str::<KeyId>("\"nothex\"").is_err());
    }
}
