//! An organization key taken out of a key store, for a holder to cache next to its access token.

use std::fmt;

use bitwarden_crypto::{BitwardenLegacyKeyBytes, KeySlotIds, KeyStoreContext, SymmetricCryptoKey};
use bitwarden_encoding::B64;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::AccessTokenError;

/// An organization key taken out of a [`bitwarden_crypto::KeyStore`], opaque to the caller, so a
/// access-token holder (e.g. Secrets Manager's state file) can cache it on disk without ever
/// handling raw key bytes. Serializes to the same base64 string [`SymmetricCryptoKey::to_base64`]
/// produces.
pub struct ExportedKey(SymmetricCryptoKey);

// Redacts the key; it is not safe to log.
impl fmt::Debug for ExportedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ExportedKey").finish_non_exhaustive()
    }
}

impl ExportedKey {
    /// Reads the key at `slot` out of `ctx`.
    pub fn from_slot<Ids: KeySlotIds>(
        ctx: &KeyStoreContext<Ids>,
        slot: Ids::Symmetric,
    ) -> Result<Self, AccessTokenError> {
        #[allow(deprecated)]
        let key = ctx.dangerous_get_symmetric_key(slot)?;
        Ok(Self(key.clone()))
    }

    /// Installs the key at `slot` in `ctx`. Consumes `self`: an exported key is only ever
    /// installed once.
    pub fn install<Ids: KeySlotIds>(
        self,
        ctx: &mut KeyStoreContext<Ids>,
        slot: Ids::Symmetric,
    ) -> Result<(), AccessTokenError> {
        let local = ctx.add_local_symmetric_key(self.0);
        ctx.persist_symmetric_key(local, slot)?;
        Ok(())
    }
}

impl Serialize for ExportedKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.to_base64().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ExportedKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let b64 = B64::deserialize(deserializer)?;
        let key_bytes = BitwardenLegacyKeyBytes::from(&b64);
        SymmetricCryptoKey::try_from(&key_bytes)
            .map(Self)
            .map_err(|_| serde::de::Error::custom("invalid exported key"))
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{KeyStore, SymmetricKeyAlgorithm, key_slot_ids};

    use super::*;

    key_slot_ids! {
        #[symmetric]
        enum TestSymmSlotId {
            Organization,
            #[local]
            Local(LocalId),
        }

        #[private]
        enum TestPrivateSlotId {
            #[local]
            Local(LocalId),
        }

        #[signing]
        enum TestSigningSlotId {
            #[local]
            Local(LocalId),
        }

        TestKeySlotIds => TestSymmSlotId, TestPrivateSlotId, TestSigningSlotId;
    }

    fn store_with_org_key(key: SymmetricCryptoKey) -> KeyStore<TestKeySlotIds> {
        let store: KeyStore<TestKeySlotIds> = KeyStore::default();
        #[allow(deprecated)]
        store
            .context_mut()
            .set_symmetric_key(TestSymmSlotId::Organization, key)
            .expect("set_symmetric_key");
        store
    }

    #[test]
    fn from_slot_then_install_round_trips() {
        let key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let issuer_store = store_with_org_key(key.clone());

        let exported =
            ExportedKey::from_slot(&issuer_store.context(), TestSymmSlotId::Organization)
                .expect("from_slot");

        let holder_store: KeyStore<TestKeySlotIds> = KeyStore::default();
        exported
            .install(
                &mut holder_store.context_mut(),
                TestSymmSlotId::Organization,
            )
            .expect("install");

        let ctx = holder_store.context();
        #[allow(deprecated)]
        let installed = ctx
            .dangerous_get_symmetric_key(TestSymmSlotId::Organization)
            .unwrap();
        assert_eq!(installed.to_base64(), key.to_base64());
    }

    #[test]
    fn from_slot_on_empty_slot_errors() {
        let store: KeyStore<TestKeySlotIds> = KeyStore::default();
        let result = ExportedKey::from_slot(&store.context(), TestSymmSlotId::Organization);
        assert!(result.is_err());
    }

    #[test]
    fn serializes_to_the_same_base64_as_to_base64() {
        let key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let store = store_with_org_key(key.clone());
        let exported =
            ExportedKey::from_slot(&store.context(), TestSymmSlotId::Organization).unwrap();

        let serialized = serde_json::to_string(&exported).unwrap();
        let expected = serde_json::to_string(&key.to_base64()).unwrap();
        assert_eq!(serialized, expected);
    }

    #[test]
    fn serde_round_trips() {
        let key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let store = store_with_org_key(key.clone());
        let exported =
            ExportedKey::from_slot(&store.context(), TestSymmSlotId::Organization).unwrap();

        let serialized = serde_json::to_string(&exported).unwrap();
        let deserialized: ExportedKey = serde_json::from_str(&serialized).unwrap();

        let holder_store: KeyStore<TestKeySlotIds> = KeyStore::default();
        deserialized
            .install(
                &mut holder_store.context_mut(),
                TestSymmSlotId::Organization,
            )
            .unwrap();

        let ctx = holder_store.context();
        #[allow(deprecated)]
        let installed = ctx
            .dangerous_get_symmetric_key(TestSymmSlotId::Organization)
            .unwrap();
        assert_eq!(installed.to_base64(), key.to_base64());
    }

    #[test]
    fn debug_output_redacts_the_key() {
        let key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let store = store_with_org_key(key.clone());
        let exported =
            ExportedKey::from_slot(&store.context(), TestSymmSlotId::Organization).unwrap();

        let debug_str = format!("{exported:?}");
        assert_eq!(debug_str, "ExportedKey(..)");
        assert!(!debug_str.contains(&key.to_base64().to_string()));
    }

    #[test]
    fn invalid_base64_fails_to_deserialize_without_echoing_input() {
        let result: Result<ExportedKey, _> = serde_json::from_str("\"not valid base64!!\"");
        let err = result.expect_err("invalid base64 must fail");
        assert!(!err.to_string().contains("not valid base64!!"));
    }

    #[test]
    fn wrong_length_fails_to_deserialize_without_echoing_input() {
        let short_key_b64 = B64::from([0u8; 15].as_slice()).to_string();
        let json = serde_json::to_string(&short_key_b64).unwrap();
        let result: Result<ExportedKey, _> = serde_json::from_str(&json);
        let err = result.expect_err("wrong length must fail");
        assert!(!err.to_string().contains(&short_key_b64));
    }
}
