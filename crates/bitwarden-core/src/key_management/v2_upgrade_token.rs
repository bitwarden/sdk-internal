//! V2 Upgrade Token allows secure bidirectional key rotation from V1 to V2 user keys.
//!
//! The token wraps each key with the other (V1 wrapped by V2, V2 wrapped by V1) and validates
//! both directions decrypt correctly to prevent tampering. This enables clients to unlock with
//! their existing V1 key and automatically receive the upgraded V2 key, or vice versa.
//!
//! The token validates bidirectional decryption on both creation and unwrapping:
//! - Creating token: Encrypts both keys, then decrypts both to verify
//! - Unwrapping: Decrypts requested key, then decrypts opposite direction to validate
//!
//! This ensures tampering is detected - an attacker can't modify one wrapped key without
//! breaking the other direction's validation.

use std::str::FromStr;

use bitwarden_crypto::{EncString, KeyDecryptable, KeyIds, KeyStoreContext, SymmetricCryptoKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::instrument;
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::FromWasmAbi;

/// V2 Upgrade Token enables bidirectional key rotation from V1 to V2 user keys.
///
/// The token contains:
/// - `wrapped_uk_1`: V1 user key encrypted with V2 key (Cose_Encrypt0_B64 format)
/// - `wrapped_uk_2`: V2 user key encrypted with V1 key (Aes256Cbc_HmacSha256_B64 format)
///
/// Both wrapping directions are validated on creation and unwrapping to prevent tampering.
#[derive(Clone, Debug)]
pub struct V2UpgradeToken {
    wrapped_uk_1: EncString,
    wrapped_uk_2: EncString,
}

impl V2UpgradeToken {
    /// Creates a new V2UpgradeToken from key IDs in the KeyStore.
    ///
    /// This encrypts V1 with V2, V2 with V1, then validates bidirectional decryption.
    ///
    /// # Arguments
    /// * `v1_key_id` - The key ID for the V1 (Aes256CbcHmac) key
    /// * `v2_key_id` - The key ID for the V2 (XChaCha20Poly1305) key
    /// * `ctx` - KeyStore context for accessing keys
    ///
    /// # Returns
    /// A validated V2UpgradeToken ready for serialization
    #[instrument(skip_all)]
    pub fn create<Ids: KeyIds>(
        v1_key_id: Ids::Symmetric,
        v2_key_id: Ids::Symmetric,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, V2UpgradeTokenError> {
        // Get the keys from the KeyStore and type-check them
        #[allow(deprecated)]
        let v1_key = ctx
            .dangerous_get_symmetric_key(v1_key_id)
            .map_err(|_| V2UpgradeTokenError::KeyMissing)?;
        match v1_key {
            SymmetricCryptoKey::Aes256CbcHmacKey(_) => {}
            _ => return Err(V2UpgradeTokenError::WrongKeyType),
        }

        #[allow(deprecated)]
        let v2_key = ctx
            .dangerous_get_symmetric_key(v2_key_id)
            .map_err(|_| V2UpgradeTokenError::KeyMissing)?;
        match v2_key {
            SymmetricCryptoKey::XChaCha20Poly1305Key(_) => {}
            _ => return Err(V2UpgradeTokenError::WrongKeyType),
        }

        // Wrap V1 key with V2 key (creates Cose_Encrypt0_B64)
        let wrapped_uk_1 = ctx
            .wrap_symmetric_key(v2_key_id, v1_key_id)
            .map_err(|_| V2UpgradeTokenError::EncryptionFailed)?;

        // Wrap V2 key with V1 key (creates Aes256Cbc_HmacSha256_B64)
        let wrapped_uk_2 = ctx
            .wrap_symmetric_key(v1_key_id, v2_key_id)
            .map_err(|_| V2UpgradeTokenError::EncryptionFailed)?;

        // Validate bidirectional decryption
        // wrapped_uk_1 is V1 encrypted with V2, so decrypt with V2
        let _: Vec<u8> = wrapped_uk_1
            .decrypt_with_key(v2_key)
            .map_err(|_| V2UpgradeTokenError::ValidationFailed)?;
        // wrapped_uk_2 is V2 encrypted with V1, so decrypt with V1
        let _: Vec<u8> = wrapped_uk_2
            .decrypt_with_key(v1_key)
            .map_err(|_| V2UpgradeTokenError::ValidationFailed)?;

        Ok(V2UpgradeToken {
            wrapped_uk_1,
            wrapped_uk_2,
        })
    }

    /// Unwraps the V1 key from the token using the V2 key.
    ///
    /// This decrypts `wrapped_uk_1` with the V2 key, validates by decrypting `wrapped_uk_2`
    /// with the extracted V1 key, then adds the V1 key to the KeyStore.
    ///
    /// # Arguments
    /// * `v2_key_id` - The key ID for the V2 key used to decrypt V1
    /// * `ctx` - Mutable KeyStore context for adding the unwrapped V1 key
    ///
    /// # Returns
    /// The key ID of the newly added V1 key in the KeyStore
    #[instrument(skip_all)]
    pub fn unwrap_v1<Ids: KeyIds>(
        &self,
        v2_key_id: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, V2UpgradeTokenError> {
        // Decrypt wrapped_uk_1 with V2 key and add V1 key to the store
        let new_v1_id = ctx
            .unwrap_symmetric_key(v2_key_id, &self.wrapped_uk_1)
            .map_err(|_| V2UpgradeTokenError::DecryptionFailed)?;

        // Validate: unwrapped V1 should be able to decrypt wrapped_uk_2
        #[allow(deprecated)]
        let v1_key = ctx
            .dangerous_get_symmetric_key(new_v1_id)
            .map_err(|_| V2UpgradeTokenError::DecryptionFailed)?;
        let _: Vec<u8> = self
            .wrapped_uk_2
            .decrypt_with_key(v1_key)
            .map_err(|_| V2UpgradeTokenError::ValidationFailed)?;

        Ok(new_v1_id)
    }

    /// Unwraps the V2 key from the token using the V1 key.
    ///
    /// This decrypts `wrapped_uk_2` with the V1 key, validates by decrypting `wrapped_uk_1`
    /// with the extracted V2 key, then adds the V2 key to the KeyStore.
    ///
    /// # Arguments
    /// * `v1_key_id` - The key ID for the V1 key used to decrypt V2
    /// * `ctx` - Mutable KeyStore context for adding the unwrapped V2 key
    ///
    /// # Returns
    /// The key ID of the newly added V2 key in the KeyStore
    #[instrument(skip_all)]
    pub fn unwrap_v2<Ids: KeyIds>(
        &self,
        v1_key_id: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, V2UpgradeTokenError> {
        // Decrypt wrapped_uk_2 with V1 key and add V2 key to the store
        let new_v2_id = ctx
            .unwrap_symmetric_key(v1_key_id, &self.wrapped_uk_2)
            .map_err(|_| V2UpgradeTokenError::DecryptionFailed)?;

        // Validate: unwrapped V2 should be able to decrypt wrapped_uk_1
        #[allow(deprecated)]
        let v2_key = ctx
            .dangerous_get_symmetric_key(new_v2_id)
            .map_err(|_| V2UpgradeTokenError::DecryptionFailed)?;
        let _: Vec<u8> = self
            .wrapped_uk_1
            .decrypt_with_key(v2_key)
            .map_err(|_| V2UpgradeTokenError::ValidationFailed)?;

        Ok(new_v2_id)
    }
}

impl FromStr for V2UpgradeToken {
    type Err = V2UpgradeTokenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        #[derive(Deserialize)]
        struct Fields {
            wrapped_uk_1: EncString,
            wrapped_uk_2: EncString,
        }
        let Fields {
            wrapped_uk_1,
            wrapped_uk_2,
        } = serde_json::from_str(s).map_err(|_| V2UpgradeTokenError::Serialization)?;
        Ok(V2UpgradeToken {
            wrapped_uk_1,
            wrapped_uk_2,
        })
    }
}

impl From<V2UpgradeToken> for String {
    fn from(val: V2UpgradeToken) -> Self {
        #[derive(Serialize)]
        struct Fields<'a> {
            wrapped_uk_1: &'a EncString,
            wrapped_uk_2: &'a EncString,
        }
        serde_json::to_string(&Fields {
            wrapped_uk_1: &val.wrapped_uk_1,
            wrapped_uk_2: &val.wrapped_uk_2,
        })
        .expect("Serialization to JSON should not fail")
    }
}

impl<'de> Deserialize<'de> for V2UpgradeToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        V2UpgradeToken::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for V2UpgradeToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&String::from(self.clone()))
    }
}

/// Errors that can occur when working with V2UpgradeToken
#[derive(Debug, Error)]
pub enum V2UpgradeTokenError {
    /// Decryption of a wrapped key failed
    #[error("Decryption failed")]
    DecryptionFailed,
    /// Bidirectional validation failed - token may be tampered with
    #[error("Validation failed")]
    ValidationFailed,
    /// Serialization or deserialization failed
    #[error("Serialization error")]
    Serialization,
    /// Wrong key type provided (expected V1 or V2)
    #[error("Wrong key type")]
    WrongKeyType,
    /// Key not found in KeyStore
    #[error("Key missing")]
    KeyMissing,
    /// Failed to encrypt a key
    #[error("Encryption failed")]
    EncryptionFailed,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type V2UpgradeToken = Tagged<string, "V2UpgradeToken">;
"#;

#[cfg(feature = "wasm")]
impl wasm_bindgen::describe::WasmDescribe for V2UpgradeToken {
    fn describe() {
        <String as wasm_bindgen::describe::WasmDescribe>::describe();
    }
}

#[cfg(feature = "wasm")]
impl FromWasmAbi for V2UpgradeToken {
    type Abi = <String as FromWasmAbi>::Abi;

    unsafe fn from_abi(abi: Self::Abi) -> Self {
        use wasm_bindgen::UnwrapThrowExt;
        let string = unsafe { String::from_abi(abi) };
        V2UpgradeToken::from_str(&string).unwrap_throw()
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{KeyStore, SymmetricKeyAlgorithm};

    use super::*;
    use crate::key_management::KeyIds;

    #[test]
    fn test_create_and_round_trip() {
        let key_store = KeyStore::<KeyIds>::default();
        let mut ctx = key_store.context_mut();

        // Create V1 and V2 keys
        let v1_key_id = ctx.generate_symmetric_key();
        let v2_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Create token
        let token = V2UpgradeToken::create(v1_key_id, v2_key_id, &ctx)
            .expect("Token creation should succeed");

        // Serialize and deserialize
        let serialized = String::from(token.clone());
        let deserialized =
            V2UpgradeToken::from_str(&serialized).expect("Deserialization should succeed");

        // Unwrap V2 using V1
        let unwrapped_v2_id = deserialized
            .unwrap_v2(v1_key_id, &mut ctx)
            .expect("Unwrapping V2 should succeed");

        // Verify the unwrapped V2 key matches original
        #[allow(deprecated)]
        let original_v2 = ctx.dangerous_get_symmetric_key(v2_key_id).unwrap();
        #[allow(deprecated)]
        let unwrapped_v2 = ctx.dangerous_get_symmetric_key(unwrapped_v2_id).unwrap();
        assert_eq!(original_v2, unwrapped_v2);
    }

    #[test]
    fn test_bidirectional_unwrap() {
        let key_store = KeyStore::<KeyIds>::default();
        let mut ctx = key_store.context_mut();

        // Create V1 and V2 keys
        let v1_key_id = ctx.generate_symmetric_key();
        let v2_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Create token
        let token = V2UpgradeToken::create(v1_key_id, v2_key_id, &ctx)
            .expect("Token creation should succeed");

        // Unwrap V2 using V1
        let unwrapped_v2_id = token
            .unwrap_v2(v1_key_id, &mut ctx)
            .expect("Unwrapping V2 should succeed");

        // Unwrap V1 using the unwrapped V2
        let unwrapped_v1_id = token
            .unwrap_v1(unwrapped_v2_id, &mut ctx)
            .expect("Unwrapping V1 should succeed");

        // Verify both unwrapped keys match originals
        #[allow(deprecated)]
        let original_v1 = ctx.dangerous_get_symmetric_key(v1_key_id).unwrap();
        #[allow(deprecated)]
        let original_v2 = ctx.dangerous_get_symmetric_key(v2_key_id).unwrap();
        #[allow(deprecated)]
        let unwrapped_v1 = ctx.dangerous_get_symmetric_key(unwrapped_v1_id).unwrap();
        #[allow(deprecated)]
        let unwrapped_v2 = ctx.dangerous_get_symmetric_key(unwrapped_v2_id).unwrap();

        assert_eq!(original_v1, unwrapped_v1);
        assert_eq!(original_v2, unwrapped_v2);
    }

    #[test]
    fn test_wrong_key_type_error() {
        let key_store = KeyStore::<KeyIds>::default();
        let mut ctx = key_store.context_mut();

        // Try to create token with two V1 keys
        let v1_key_1 = ctx.generate_symmetric_key();
        let v1_key_2 = ctx.generate_symmetric_key();

        let result = V2UpgradeToken::create(v1_key_1, v1_key_2, &ctx);
        assert!(matches!(result, Err(V2UpgradeTokenError::WrongKeyType)));
    }

    #[test]
    fn test_serialization_format() {
        let key_store = KeyStore::<KeyIds>::default();
        let mut ctx = key_store.context_mut();

        let v1_key_id = ctx.generate_symmetric_key();
        let v2_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let token = V2UpgradeToken::create(v1_key_id, v2_key_id, &ctx)
            .expect("Token creation should succeed");

        // Verify serialization produces a JSON object with the expected fields
        let serialized = String::from(token.clone());
        let json: serde_json::Value =
            serde_json::from_str(&serialized).expect("Should be valid JSON");
        assert!(json.get("wrapped_uk_1").is_some());
        assert!(json.get("wrapped_uk_2").is_some());

        // Verify deserialization round-trips
        let deserialized = V2UpgradeToken::from_str(&serialized);
        assert!(deserialized.is_ok());
    }
}
