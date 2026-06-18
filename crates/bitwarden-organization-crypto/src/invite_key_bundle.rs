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

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_INVITE_KEY_DATA: &'static str = r#"
export type InviteKeyData = Tagged<string, "InviteKeyData">;
"#;

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

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_INVITE: &'static str = r#"
export type Invite = Tagged<string, "Invite">;
"#;

/// Cryptographic invite for an organization.
#[derive(Debug, Clone)]
pub struct Invite {
    organization_key_wrapped_invite_key: EncString,
    // Milestone 3:
    // invite_key_wrapped_organization_key: Option<EncString>
}

/// Wire format for [`Invite`]. This is what's serialized by serde
#[derive(Serialize, Deserialize)]
struct InviteData {
    organization_key_wrapped_invite_key: EncString,
}

impl From<&Invite> for InviteData {
    fn from(envelope: &Invite) -> Self {
        InviteData {
            organization_key_wrapped_invite_key: envelope
                .organization_key_wrapped_invite_key
                .clone(),
        }
    }
}

impl From<&Invite> for String {
    fn from(key_data: &Invite) -> Self {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&InviteData::from(key_data), &mut buf)
            .expect("CBOR serialization of InviteKeyEnvelope never fails");
        B64::from(buf).to_string()
    }
}

impl FromStr for Invite {
    type Err = InviteKeyBundleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = B64::try_from(s)
            .map_err(|_| InviteKeyBundleError::DecodingFailed)?
            .into_bytes();
        let data: InviteData = ciborium::de::from_reader(bytes.as_slice())
            .map_err(|_| InviteKeyBundleError::DecodingFailed)?;
        Ok(Invite {
            organization_key_wrapped_invite_key: data.organization_key_wrapped_invite_key,
        })
    }
}

impl<'de> Deserialize<'de> for Invite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl Serialize for Invite {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&String::from(self))
    }
}

impl Invite {
    /// Given a correct organization key, unseals the `InviteKeyEnvelope`,
    /// returning the `InviteKeyData` sealed inside.
    pub fn unseal<Ids: KeySlotIds>(
        &self,
        organization_key: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<InviteKeyData, InviteKeyBundleError> {
        let key_id = ctx
            .unwrap_symmetric_key(organization_key, &self.organization_key_wrapped_invite_key)
            .map_err(|_| InviteKeyBundleError::KeyUnsealingFailed)?;

        #[allow(deprecated)]
        Ok(InviteKeyData(
            ctx.dangerous_get_symmetric_key(key_id)
                .map_err(|_| InviteKeyBundleError::MissingKeyId(format!("{key_id:?}")))?
                .clone(),
        ))
    }

    #[allow(unused)]
    fn enable_confirmation<Ids: KeySlotIds>(
        &mut self,
        _organization_key: Ids::Symmetric,
        _ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<(), InviteKeyBundleError> {
        unimplemented!("Confirmation is not yet supported in this version of the crate");
    }

    #[allow(unused)]
    fn disable_confirmation(&mut self) {
        unimplemented!("Confirmation is not yet supported in this version of the crate");
    }

    #[allow(unused)]
    fn supports_confirmation() -> bool {
        false
    }

    #[allow(unused)]
    fn unseal_organization_key<Ids: KeySlotIds>(
        &self,
        _invite_key: &InviteKeyData,
        _target_key_slot: Ids::Symmetric,
        _ctx: &mut KeyStoreContext<impl KeySlotIds>,
    ) -> Result<SymmetricCryptoKey, InviteKeyBundleError> {
        unimplemented!("Confirmation is not yet supported in this version of the crate");
    }

    #[allow(unused)]
    fn update_organization_key<Ids: KeySlotIds>(
        &mut self,
        _old_organization_key: Ids::Symmetric,
        _new_organization_key: Ids::Symmetric,
        _ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<(), InviteKeyBundleError> {
        unimplemented!(
            "Organization key rotation is not yet supported in this version of the crate"
        );
    }
}

/// A struct for holding the invitation key and the invite
#[derive(Debug)]
pub struct InviteBundle {
    // The unencrypted invite key. IMPORTANT: This must never be sent to the server
    invite_key: InviteKeyData,
    // The cryptographic invite
    invite: Invite,
}

impl InviteBundle {
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

        let sealed_key_envelope =
            Invite {
                organization_key_wrapped_invite_key: ctx
                    .wrap_symmetric_key(organization_key, key_id)
                    .map_err(|_| InviteKeyBundleError::KeySealingFailed)?,
            };

        Ok(Self {
            invite_key: raw_key_data,
            invite: sealed_key_envelope,
        })
    }

    /// Get the raw invite key bytes using `InviteKeyData`
    /// CRITICAL: this data MUST NOT be sent to the server
    ///
    /// This can be base64url encoded for URL use only:
    /// ```ignore
    /// let key: &InviteKeyData = bundle.dangerous_get_raw_invite_key();
    /// let key_bytes: String = String::from(key);
    /// ```
    pub fn dangerous_get_raw_invite_key(&self) -> &InviteKeyData {
        &self.invite_key
    }

    /// Gets the sealed invite key (wrapped using the organization key)
    pub fn get_envelope(&self) -> &Invite {
        &self.invite
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{BitwardenLegacyKeyBytes, KeyStore, SymmetricCryptoKey, key_slot_ids};
    use bitwarden_encoding::{B64, B64Url};

    use crate::invite_key_bundle::{Invite, InviteBundle, InviteKeyData};

    #[test]
    fn test_basic_invitation_envelope_bundle() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let local_org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();

        let key1 = InviteBundle::make(TestSymmKey::Organization, &mut ctx).unwrap();
        let key2 = InviteBundle::make(TestSymmKey::Organization, &mut ctx).unwrap();

        assert_ne!(key1.invite_key.0, key2.invite_key.0);
    }

    #[test]
    fn test_envelope_unseals_to_raw_bytes() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let local_org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();

        let key = InviteBundle::make(TestSymmKey::Organization, &mut ctx).unwrap();

        let unsealed_key = ctx
            .unwrap_symmetric_key(
                TestSymmKey::Organization,
                &key.invite.organization_key_wrapped_invite_key,
            )
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

        let key = InviteBundle::make(TestSymmKey::Organization, &mut ctx).unwrap();

        let raw_key_id = ctx.add_local_symmetric_key(key.dangerous_get_raw_invite_key().0.clone());

        let unsealed_key = ctx
            .unwrap_symmetric_key(
                TestSymmKey::Organization,
                &key.invite.organization_key_wrapped_invite_key,
            )
            .unwrap();

        #[allow(deprecated)]
        let raw_key = ctx.dangerous_get_symmetric_key(raw_key_id).unwrap().clone();
        #[allow(deprecated)]
        let unsealed = ctx
            .dangerous_get_symmetric_key(unsealed_key)
            .unwrap()
            .clone();
        assert_eq!(raw_key, unsealed);
    }

    #[test]
    fn test_envelope_round_trip_unseals_to_key_data() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let local_org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();

        let key_bundle = InviteBundle::make(TestSymmKey::Organization, &mut ctx).unwrap();
        let raw_key_data = key_bundle.dangerous_get_raw_invite_key();
        let sealed_key_envelope = key_bundle.get_envelope();
        let unsealed_raw_key_data = sealed_key_envelope
            .unseal(TestSymmKey::Organization, &mut ctx)
            .unwrap();

        assert_eq!(raw_key_data, &unsealed_raw_key_data);

        let internal_unwrapped_key_id = ctx
            .unwrap_symmetric_key(
                TestSymmKey::Organization,
                &key_bundle.invite.organization_key_wrapped_invite_key,
            )
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
    fn test_envelope_string_round_trip() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let local_org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();

        let bundle = InviteBundle::make(TestSymmKey::Organization, &mut ctx).unwrap();
        let envelope = bundle.get_envelope();

        let encoded = String::from(envelope);
        let decoded: Invite = encoded.parse().unwrap();

        assert_eq!(String::from(&decoded), encoded);

        // The custom serde impls delegate to the string round-trip.
        let json = serde_json::to_string(envelope).unwrap();
        let from_json: Invite = serde_json::from_str(&json).unwrap();
        assert_eq!(String::from(&from_json), encoded);
    }

    #[test]
    fn test_into_base64_url() {
        let data = b"+/=Hello, World!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key =
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(data.to_vec())).unwrap();

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

    // Test vectors captured from `generate_test_vectors`. These freeze a real sealed
    // envelope so that backward compatibility (old data must remain decryptable) is
    // verified by `test_invite_key_envelope_test_vector`.
    const TEST_VECTOR_ORG_KEY: &str =
        "KGP9Nc2/91w+42Z9VzY0m7h18avuZcq4ICM8Rhdc3BD92LbWS2TQkVBzavvUM684WKXiC22NJi2EwaiDW4YTAA==";
    const TEST_VECTOR_ENVELOPE: &str = "oXgjb3JnYW5pemF0aW9uX2tleV93cmFwcGVkX2ludml0ZV9rZXl4tDIuNlRoNk1FZUJ1L0h0V0FIbFBEN01mZz09fG5FUkx1b3NjelRVMUpSbm81Y2dMYW51cnczd2gxb3dJM2QrdmUrbVJTT1g0M2ZkcE9KRmU1aFhzazhKcXVXcXlIMFBTT0ZHVGFVNkFDK0h6L3plQUF1RTFLZEpSVDRBTVFVVSs0NXJOR3hrPXxpM0tQeGIvWmRIL3ZBcGJENUVQUVplNWFXZ011RDMvWm4xNmFmNzgveFdJPQ==";
    const TEST_VECTOR_INVITE_KEY: &str = "pQEEAlD8Oee8YLwqCdiV6AmNkSKkAzoAARFvBIQDBAUGIFgg7bQ4KpPzD2wLsWK-eCtFYhO5-rXEQaWzaxSlX7egtC4B";

    #[test]
    #[ignore = "Manual test to generate test vectors"]
    fn generate_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let local_org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();

        let bundle = InviteBundle::make(TestSymmKey::Organization, &mut ctx).unwrap();

        #[allow(deprecated)]
        let org_key = ctx
            .dangerous_get_symmetric_key(TestSymmKey::Organization)
            .unwrap();

        println!(
            "const TEST_VECTOR_ORG_KEY: &str = \"{}\";",
            B64::from(org_key.to_encoded())
        );
        println!(
            "const TEST_VECTOR_ENVELOPE: &str = \"{}\";",
            String::from(bundle.get_envelope())
        );
        println!(
            "const TEST_VECTOR_INVITE_KEY: &str = \"{}\";",
            String::from(bundle.dangerous_get_raw_invite_key())
        );
    }

    #[test]
    fn test_invite_key_envelope_test_vector() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let org_key =
            SymmetricCryptoKey::try_from(B64::try_from(TEST_VECTOR_ORG_KEY).unwrap()).unwrap();
        let org_key_id = ctx.add_local_symmetric_key(org_key);

        let envelope: Invite = TEST_VECTOR_ENVELOPE.parse().unwrap();
        let unsealed = envelope.unseal(org_key_id, &mut ctx).unwrap();

        assert_eq!(String::from(&unsealed), TEST_VECTOR_INVITE_KEY);
    }

    #[test]
    #[ignore = "Manual test to verify debug format"]
    fn test_debug() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(org_key_id, TestSymmKey::Organization)
            .unwrap();

        let bundle = InviteBundle::make(TestSymmKey::Organization, &mut ctx).unwrap();
        // Exercises both the `InviteKeyData` and `InviteKeyEnvelope` `Debug` impls.
        println!("{bundle:?}");
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
