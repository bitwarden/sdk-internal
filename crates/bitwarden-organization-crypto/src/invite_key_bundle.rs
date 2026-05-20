use std::str::FromStr;

use bitwarden_crypto::{
    BitwardenLegacyKeyBytes, EncString, KeySlotIds, KeyStoreContext, SymmetricCryptoKey,
};
use bitwarden_encoding::{B64, B64Url, FromStrVisitor};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;

/// Errors that can occur when creating an invite key envelope
#[derive(Debug, Error)]
pub enum InviteKeyBundleError {
    /// Decoding the encrypted InviteKeyEnvelope failed
    #[error("Decoding failed")]
    DecodingFailed,
    /// Encoding the encrypted InviteKeyEnvelope failed
    #[error("Encoding failed")]
    EncodingFailed,
    /// The key wrapping failed while using the provided organization key
    #[error("Unable to seal invite key with org key")]
    KeySealingFailed,
    /// The key unsealing failed while using the provided organization key
    #[error("Unable to unseal invite key with org key")]
    KeyUnsealingFailed,
    /// The key_id was not found in the key context store
    #[error("Missing Key for Id: {0}")]
    MissingKeyId(String),
}

/// Struct for holding the Invite Key's raw byte data. Supports WASM bindings,
/// automatically using base64Url encoding for both `wasm-bindgen` and `tsify`.
///
/// To manually encode as a `base64URL` string:
/// ```ignore
/// let key = SymmetricCryptoKey::try_from(...);
/// String::from(&InviteKeyData(key));
/// ```
/// Also supports serde serialization/deserialization using the base64Url format
#[derive(Clone)]
pub struct InviteKeyData(SymmetricCryptoKey);

impl ConstantTimeEq for InviteKeyData {
    fn ct_eq(&self, other: &InviteKeyData) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for InviteKeyData {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl std::fmt::Debug for InviteKeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<&InviteKeyData> for String {
    fn from(key_data: &InviteKeyData) -> Self {
        B64Url::from(key_data.0.to_encoded().as_ref()).to_string()
    }
}

impl FromStr for InviteKeyData {
    type Err = InviteKeyBundleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = B64Url::try_from(s).map_err(|_| InviteKeyBundleError::DecodingFailed)?;
        Ok(InviteKeyData(
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(data.as_bytes()))
                .map_err(|_| InviteKeyBundleError::DecodingFailed)?,
        ))
    }
}

impl<'de> Deserialize<'de> for InviteKeyData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl Serialize for InviteKeyData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&String::from(self))
    }
}

/// Struct for holding the wrapped invite key data. Currently supports encstring
/// but the inner type must remain private as it may be extended in the future.
pub struct InviteKeyEnvelope(EncString);

impl From<&InviteKeyEnvelope> for String {
    fn from(key_data: &InviteKeyEnvelope) -> Self {
        B64::from(
            key_data
                .0
                .to_buffer()
                .expect("`to_buffer` never fails for `EncString`"),
        )
        .to_string()
    }
}

impl FromStr for InviteKeyEnvelope {
    type Err = InviteKeyBundleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = B64::try_from(s).map_err(|_| InviteKeyBundleError::DecodingFailed)?;
        Ok(InviteKeyEnvelope(
            EncString::from_buffer(data.as_bytes())
                .map_err(|_| InviteKeyBundleError::DecodingFailed)?,
        ))
    }
}

impl<'de> Deserialize<'de> for InviteKeyEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl Serialize for InviteKeyEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&String::from(self))
    }
}

impl InviteKeyEnvelope {
    /// Given a correct organization key, unseals the `IniteKeyEnvelope`,
    /// returning the `InviteKeyData` sealed inside.
    pub fn unseal<Ids: KeySlotIds>(
        &self,
        organization_key: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<InviteKeyData, InviteKeyBundleError> {
        let key_id = ctx
            .unwrap_symmetric_key(organization_key, &self.0)
            .map_err(|_| InviteKeyBundleError::KeyUnsealingFailed)?;

        #[allow(deprecated)]
        Ok(InviteKeyData(
            ctx.dangerous_get_symmetric_key(key_id)
                .map_err(|_| InviteKeyBundleError::MissingKeyId(format!("{key_id:?}")))?
                .clone(),
        ))
    }
}

/// A struct for holding the invitation key and the invitation key sealed by
/// the organization key
pub struct InviteKeyBundle {
    raw_key_data: InviteKeyData,
    sealed_key_envelope: InviteKeyEnvelope,
}

impl InviteKeyBundle {
    /// Generates a brand new invitation key and wraps it with the provided
    /// organization key.
    pub fn make<Ids: KeySlotIds>(
        organization_key: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Self, InviteKeyBundleError> {
        let key_id =
            ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::XChaCha20Poly1305);

        #[allow(deprecated)]
        let raw_key_data = InviteKeyData(
            ctx.dangerous_get_symmetric_key(key_id)
                .map_err(|_| InviteKeyBundleError::MissingKeyId(format!("{key_id:?}")))?
                .clone(),
        );

        let sealed_key_envelope = InviteKeyEnvelope(
            ctx.wrap_symmetric_key(organization_key, key_id)
                .map_err(|_| InviteKeyBundleError::KeySealingFailed)?,
        );

        Ok(Self {
            raw_key_data,
            sealed_key_envelope,
        })
    }

    /// Get the raw invite key bytes using `InviteKeyData`
    /// CRITICAL: this data MUST NOT be sent to the server
    ///
    /// This can be base64 encoded for URL use only:
    /// ```ignore
    /// let key: &InviteKeyData = bundle.dangerous_get_invite_key();
    /// let key_bytes: B64Url = B64Url::from(key);
    /// ```
    pub fn dangerous_get_raw_invite_key(&self) -> &InviteKeyData {
        &self.raw_key_data
    }

    /// Gets the sealed invite key (wrapped using the organization key)
    pub fn get_sealed_invite_key_envelope(&self) -> &InviteKeyEnvelope {
        &self.sealed_key_envelope
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{BitwardenLegacyKeyBytes, KeyStore, SymmetricCryptoKey, key_slot_ids};
    use bitwarden_encoding::B64Url;

    use crate::invite_key_bundle::{InviteKeyBundle, InviteKeyData};

    #[test]
    fn test_basic_invitation_envelope_bundle() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let local_org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();

        let key1 = InviteKeyBundle::make(TestSymmKey::Organization, &mut ctx).unwrap();
        let key2 = InviteKeyBundle::make(TestSymmKey::Organization, &mut ctx).unwrap();

        assert_ne!(key1.raw_key_data.0, key2.raw_key_data.0);
    }

    #[test]
    fn test_envelope_unseals_to_raw_bytes() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let local_org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();

        let key = InviteKeyBundle::make(TestSymmKey::Organization, &mut ctx).unwrap();

        let unsealed_key = ctx
            .unwrap_symmetric_key(TestSymmKey::Organization, &key.sealed_key_envelope.0)
            .unwrap();

        #[allow(deprecated)]
        let unsealed_key = ctx
            .dangerous_get_symmetric_key(unsealed_key)
            .unwrap()
            .clone();

        assert_eq!(key.dangerous_get_raw_invite_key().0, unsealed_key);
    }

    #[test]
    fn test_envelope_unseals_to_same_key_as_raw_data() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let local_org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();

        let key = InviteKeyBundle::make(TestSymmKey::Organization, &mut ctx).unwrap();

        let raw_key_id = ctx.add_local_symmetric_key(key.dangerous_get_raw_invite_key().0.clone());

        let unsealed_key = ctx
            .unwrap_symmetric_key(TestSymmKey::Organization, &key.sealed_key_envelope.0)
            .unwrap();

        ctx.assert_symmetric_keys_equal(raw_key_id, unsealed_key);
    }

    #[test]
    fn test_envelope_round_trip_unseals_to_key_data() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let local_org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();

        let key_bundle = InviteKeyBundle::make(TestSymmKey::Organization, &mut ctx).unwrap();
        let raw_key_data = key_bundle.dangerous_get_raw_invite_key();
        let sealed_key_envelope = key_bundle.get_sealed_invite_key_envelope();
        let unsealed_raw_key_data = sealed_key_envelope
            .unseal(TestSymmKey::Organization, &mut ctx)
            .unwrap();

        assert_eq!(raw_key_data, &unsealed_raw_key_data);

        let internal_unwrapped_key_id = ctx
            .unwrap_symmetric_key(TestSymmKey::Organization, &key_bundle.sealed_key_envelope.0)
            .unwrap();

        #[allow(deprecated)]
        let internal_unwrapped_key = ctx
            .dangerous_get_symmetric_key(internal_unwrapped_key_id)
            .unwrap()
            .clone();

        let b64url_encoded_unsealed_key =
            B64Url::from(internal_unwrapped_key.to_encoded().as_ref());

        assert_eq!(
            String::from(&unsealed_raw_key_data),
            b64url_encoded_unsealed_key.to_string()
        );
    }

    #[test]
    fn test_into_base64_url() {
        let data = b"+/=Hello, World!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key =
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(data.to_vec())).unwrap();
        // let expected_raw_key_data = key.to_encoded().to_vec();

        let encoded = String::from(&InviteKeyData(key));

        assert_eq!(
            encoded,
            "Ky89SGVsbG8sIFdvcmxkIUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
        );
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));

        let decoded = B64Url::try_from(encoded.as_str()).unwrap();
        assert_eq!(decoded.as_bytes(), data);
    }

    key_slot_ids! {
        #[symmetric]
        pub enum TestSymmKey {
            Organization,
            #[local]
            Local(LocalId),
        }

        #[private]
        pub enum TestPrivateKey {
            A(u8),
            B,
            #[local]
            C(LocalId),
        }

        #[signing]
        pub enum TestSigningKey {
            A(u8),
            B,
            #[local]
            C(LocalId),
        }

       pub TestIds => TestSymmKey, TestPrivateKey, TestSigningKey;
    }
}
