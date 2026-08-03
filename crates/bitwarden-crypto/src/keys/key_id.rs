use std::{fmt::Display, str::FromStr};

use rand::RngExt;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use subtle::ConstantTimeEq;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::{FromWasmAbi, IntoWasmAbi, OptionFromWasmAbi};
use zeroize::Zeroize;

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type KeyId = Tagged<string, "KeyId">;
"#;

/// Since `KeyId` is a wrapper around UUIDs, this is statically 16 bytes.
pub(crate) const KEY_ID_SIZE: usize = 16;

/// Errors that can occur when parsing a key id.
#[derive(Debug, Error)]
pub enum KeyIdError {
    /// The value is not a valid key id: not hex, or not exactly `KEY_ID_SIZE` bytes.
    #[error("Invalid key id")]
    InvalidKeyId,
}

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

    /// Returns the key ID as a lowercase hex string. A key ID is not secret; this is the
    /// representation used when reporting the ID of the current user key to the server.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

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

        let hex_encoded_key_id = unsafe { String::from_abi(abi) };
        Self::from_str(&hex_encoded_key_id).unwrap_throw()
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
        self.to_hex().into_abi()
    }
}

#[cfg(feature = "wasm")]
impl TryFrom<wasm_bindgen::JsValue> for KeyId {
    type Error = KeyIdError;

    fn try_from(value: wasm_bindgen::JsValue) -> Result<Self, Self::Error> {
        let hex_encoded_key_id = value.as_string().ok_or(KeyIdError::InvalidKeyId)?;
        Self::from_str(&hex_encoded_key_id)
    }
}

impl Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for KeyId {
    type Err = KeyIdError;

    fn from_str(hex_encoded_key_id: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(hex_encoded_key_id).map_err(|_| KeyIdError::InvalidKeyId)?;
        Self::try_from(bytes.as_slice())
    }
}

impl Serialize for KeyId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex_encoded_key_id = String::deserialize(deserializer)?;
        Self::from_str(&hex_encoded_key_id).map_err(D::Error::custom)
    }
}

impl TryFrom<&[u8]> for KeyId {
    type Error = KeyIdError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != KEY_ID_SIZE {
            return Err(KeyIdError::InvalidKeyId);
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

    #[test]
    fn test_to_hex_is_lowercase_and_fixed_length() {
        let key_id: KeyId = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]
        .into();

        assert_eq!(key_id.to_hex(), "0123456789abcdeffedcba9876543210");
        assert_eq!(key_id.to_hex().len(), KEY_ID_SIZE * 2);
    }

    #[test]
    fn test_from_str_round_trips() {
        let key_id = KeyId::make();

        let parsed: KeyId = key_id.to_hex().parse().expect("hex should parse");

        assert_eq!(key_id, parsed);
    }

    #[test]
    fn test_from_str_rejects_invalid_values() {
        // Not hex, and hex of the wrong length.
        for invalid in ["not-hex", "0123456789abcdef", ""] {
            assert!(matches!(
                invalid.parse::<KeyId>(),
                Err(KeyIdError::InvalidKeyId)
            ));
        }
    }

    #[test]
    fn test_try_from_slice_rejects_the_wrong_length() {
        assert!(matches!(
            KeyId::try_from([0u8; 4].as_slice()),
            Err(KeyIdError::InvalidKeyId)
        ));
    }

    #[test]
    fn test_serializes_as_a_bare_hex_string() {
        let key_id: KeyId = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]
        .into();

        let serialized = serde_json::to_string(&key_id).expect("serialization should succeed");
        assert_eq!(serialized, "\"0123456789abcdeffedcba9876543210\"");

        let deserialized: KeyId =
            serde_json::from_str(&serialized).expect("deserialization should succeed");
        assert_eq!(deserialized, key_id);
    }

    #[test]
    fn test_deserialization_rejects_invalid_values() {
        assert!(serde_json::from_str::<KeyId>("\"not-hex\"").is_err());
        assert!(serde_json::from_str::<KeyId>("\"abcd\"").is_err());
        assert!(serde_json::from_str::<KeyId>("123").is_err());
    }

    #[test]
    fn test_to_hex_round_trips_through_try_from_slice() {
        let key_id = KeyId::make();

        let bytes = hex::decode(key_id.to_hex()).expect("to_hex should produce valid hex");
        let round_tripped =
            KeyId::try_from(bytes.as_slice()).expect("decoded bytes should be a valid key id");

        assert_eq!(key_id, round_tripped);
    }
}
