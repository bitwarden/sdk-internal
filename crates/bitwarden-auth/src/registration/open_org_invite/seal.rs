//! Seals an open-organization-invite context into an opaque wire artifact plus a paired
//! [`HighEntropySecret`]. The sealed data rides the verification email URL; the secret stays
//! client-side. Both are needed to recover the original invite context via [`super::unseal`].
//!
//! Two-envelope construction mirrors the pattern in
//! `bitwarden-organization-crypto/src/invite_key_bundle.rs`:
//! - inner [`DataEnvelope`] seals the `RegistrationOpenOrgInviteData` payload with a freshly
//!   generated content-encryption key (CEK);
//! - outer [`SecretProtectedKeyEnvelope`] seals that CEK with a per-registration
//!   [`HighEntropySecret`].
//!
//! Substitution defense at both layers is the AES-GCM auth tag / wrong-key check — the SDK
//! performs no post-decrypt equality check on the plaintext, matching how
//! `Invite::unseal` in `invite_key_bundle` trusts the crypto.

use std::str::FromStr;

use bitwarden_core::key_management::KeySlotIds;
use bitwarden_crypto::{
    KeyStore,
    safe::{
        DataEnvelope, HighEntropySecret, SecretProtectedKeyEnvelope,
        SecretProtectedKeyEnvelopeNamespace,
    },
};
use bitwarden_encoding::{B64Url, FromStrVisitor};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::{RegistrationOpenOrgInviteData, wire_v1::RegistrationOpenOrgInviteDataV1};
use crate::registration::registration_client::{RegistrationClient, RegistrationError};

/// Byte length of the per-registration [`HighEntropySecret`] the seal path generates. 32 bytes
/// = 256 bits, well above [`HighEntropySecret`]'s minimum-length floor and matching the
/// standard random-secret size elsewhere in the SDK.
pub(super) const OPEN_ORG_INVITE_SECRET_SIZE_BYTES: usize = 32;

/// Input to [`RegistrationClient::seal_open_org_invite_data`]. All three fields are required.
// Not `uniffi::Record`-derived: [`SealedOpenOrgInvite`] holds typed cryptographic fields
// (`HighEntropySecret`, `SealedEnvelopePair`) that lack uniffi custom-type impls, so this
// crossing is WASM-only. Add those impls in `bitwarden-crypto` before enabling mobile.
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OpenOrgInviteSealRequest {
    /// The organization the registrant is joining.
    pub organization_id: String,
    /// The public invite link code carried in the shared invite URL.
    pub invite_link_code: String,
    /// The invite key associated with the invite link.
    pub invite_key: String,
}

/// Sealed open-organization-invite payload. Produced by
/// [`RegistrationClient::seal_open_org_invite_data`] and consumed by
/// [`RegistrationClient::unseal_open_org_invite_data`]. Both fields are required to unseal;
/// neither half is useful on its own.
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SealedOpenOrgInvite {
    /// URL-safe opaque payload; place on the verification-email link.
    pub sealed_data: SealedEnvelopePair,
    /// Paired secret; keep client-side (e.g. `localStorage`) and never send to the server.
    pub high_entropy_secret: HighEntropySecret,
}

/// The two sealed envelopes that together carry an open-organization-invite payload.
#[derive(Debug, Clone)]
pub struct SealedEnvelopePair {
    /// The sealed invite-payload envelope.
    pub data_envelope: DataEnvelope,
    /// The sealed content-encryption-key envelope.
    pub key_envelope: SecretProtectedKeyEnvelope,
}

impl FromStr for SealedEnvelopePair {
    type Err = SealedEnvelopePairError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let outer = B64Url::try_from(s).map_err(|_| SealedEnvelopePairError::Malformed)?;
        let wire: SealedEnvelopePairWire = ciborium::de::from_reader(outer.as_bytes())
            .map_err(|_| SealedEnvelopePairError::Malformed)?;
        let data_envelope = DataEnvelope::from(wire.data_envelope);
        let key_envelope = SecretProtectedKeyEnvelope::try_from(&wire.key_envelope)
            .map_err(|_| SealedEnvelopePairError::Malformed)?;
        Ok(SealedEnvelopePair {
            data_envelope,
            key_envelope,
        })
    }
}

impl From<&SealedEnvelopePair> for String {
    fn from(val: &SealedEnvelopePair) -> Self {
        let data_bytes: Vec<u8> = (&val.data_envelope).into();
        let key_bytes: Vec<u8> = (&val.key_envelope).into();
        let wire = SealedEnvelopePairWire {
            data_envelope: data_bytes,
            key_envelope: key_bytes,
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&wire, &mut buf)
            .expect("CBOR encoding of two byte fields cannot fail");
        B64Url::from(buf).to_string()
    }
}

impl From<SealedEnvelopePair> for String {
    fn from(val: SealedEnvelopePair) -> Self {
        (&val).into()
    }
}

impl Serialize for SealedEnvelopePair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&String::from(self))
    }
}

impl<'de> Deserialize<'de> for SealedEnvelopePair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

/// Internal CBOR framing shape for [`SealedEnvelopePair`]. Each field is the direct
/// serialization of the respective envelope type, forced to CBOR `bstr` (major type 2) via
/// `serde_bytes` for compactness — serde's default `Vec<u8>` handling would emit a CBOR array
/// of integers roughly doubling the encoded size.
#[derive(Serialize, Deserialize)]
struct SealedEnvelopePairWire {
    #[serde(rename = "d", with = "serde_bytes")]
    data_envelope: Vec<u8>,
    #[serde(rename = "k", with = "serde_bytes")]
    key_envelope: Vec<u8>,
}

/// Errors returned when parsing a [`SealedEnvelopePair`] from its wire form.
#[derive(Debug, Error)]
pub enum SealedEnvelopePairError {
    /// The wire string could not be decoded.
    #[error("Sealed envelope pair is malformed")]
    Malformed,
}

// WASM ABI: `SealedEnvelopePair` marshals as its wire string, matching the JSON wire form.
#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type SealedEnvelopePair = Tagged<String, "SealedEnvelopePair">;
"#;

#[cfg(feature = "wasm")]
impl wasm_bindgen::describe::WasmDescribe for SealedEnvelopePair {
    fn describe() {
        <String as wasm_bindgen::describe::WasmDescribe>::describe();
    }
}

#[cfg(feature = "wasm")]
impl wasm_bindgen::convert::FromWasmAbi for SealedEnvelopePair {
    type Abi = <String as wasm_bindgen::convert::FromWasmAbi>::Abi;

    unsafe fn from_abi(abi: Self::Abi) -> Self {
        use wasm_bindgen::UnwrapThrowExt;
        let string = unsafe { String::from_abi(abi) };
        SealedEnvelopePair::from_str(&string).unwrap_throw()
    }
}

#[cfg(feature = "wasm")]
impl wasm_bindgen::convert::OptionFromWasmAbi for SealedEnvelopePair {
    fn is_none(abi: &Self::Abi) -> bool {
        <String as wasm_bindgen::convert::OptionFromWasmAbi>::is_none(abi)
    }
}

#[cfg(feature = "wasm")]
impl wasm_bindgen::convert::IntoWasmAbi for SealedEnvelopePair {
    type Abi = <String as wasm_bindgen::convert::IntoWasmAbi>::Abi;

    fn into_abi(self) -> Self::Abi {
        String::from(self).into_abi()
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl RegistrationClient {
    /// Seals an [`OpenOrgInviteSealRequest`] into a [`SealedOpenOrgInvite`]. The returned
    /// `sealed_data` is safe to place on the verification-email link; the returned
    /// `high_entropy_secret` must stay client-side.
    pub fn seal_open_org_invite_data(
        &self,
        input: OpenOrgInviteSealRequest,
    ) -> Result<SealedOpenOrgInvite, RegistrationError> {
        // The CEK is transient and never persists across calls. A per-call `KeyStore` keeps
        // the key material scoped to this operation so nothing lingers in the caller's key
        // store.
        let key_store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = key_store.context_mut();

        let high_entropy_secret = HighEntropySecret::make(OPEN_ORG_INVITE_SECRET_SIZE_BYTES)
            .map_err(|_| RegistrationError::Crypto)?;

        let versioned: RegistrationOpenOrgInviteData = RegistrationOpenOrgInviteDataV1 {
            organization_id: input.organization_id,
            invite_link_code: input.invite_link_code,
            invite_key: input.invite_key,
        }
        .into();

        let (data_envelope, cek_id) =
            DataEnvelope::seal(versioned, &mut ctx).map_err(|_| RegistrationError::Crypto)?;

        let key_envelope = SecretProtectedKeyEnvelope::seal(
            cek_id,
            &high_entropy_secret,
            SecretProtectedKeyEnvelopeNamespace::RegistrationOpenOrgInvite,
            &ctx,
        )
        .map_err(|_| RegistrationError::Crypto)?;

        Ok(SealedOpenOrgInvite {
            sealed_data: SealedEnvelopePair {
                data_envelope,
                key_envelope,
            },
            high_entropy_secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::Client;

    use super::*;

    fn sample_input() -> OpenOrgInviteSealRequest {
        OpenOrgInviteSealRequest {
            organization_id: "1bc9ac1e-f5aa-45f2-94bf-b181009709b8".to_string(),
            invite_link_code: "abcd1234efgh5678".to_string(),
            invite_key: "raw-invite-key-material-base64url".to_string(),
        }
    }

    #[test]
    fn seal_produces_populated_sealed_data_and_high_entropy_secret() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let sealed = registration_client
            .seal_open_org_invite_data(sample_input())
            .expect("seal should succeed");

        // Wire round-trip sanity: the sealed envelope pair should serialize to a non-empty
        // base64url string that parses back into the same shape.
        let wire = String::from(&sealed.sealed_data);
        assert!(!wire.is_empty());
        let parsed: SealedEnvelopePair = wire.parse().expect("wire form must round-trip");
        // Just check both envelope fields are structurally present (the underlying envelopes
        // don't derive PartialEq).
        let _ = parsed.data_envelope;
        let _ = parsed.key_envelope;

        // High-entropy secret should also round-trip via its own wire form.
        let secret_wire = String::from(sealed.high_entropy_secret);
        assert!(!secret_wire.is_empty());
        secret_wire
            .parse::<HighEntropySecret>()
            .expect("high_entropy_secret must be a valid wire string");
    }

    #[test]
    fn sealed_envelope_pair_wire_is_valid_base64url() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let sealed = registration_client
            .seal_open_org_invite_data(sample_input())
            .expect("seal should succeed");

        // Wire-format sanity: the SealedEnvelopePair's wire form must decode as base64url and
        // re-encode identically.
        let wire = String::from(&sealed.sealed_data);
        let decoded =
            B64Url::try_from(wire.as_str()).expect("sealed_data wire must be valid base64url");
        assert_eq!(B64Url::from(decoded.as_bytes()).to_string(), wire);
    }

    #[test]
    fn sealed_open_org_invite_json_wire_shape_is_stable() {
        // Locks in the JSON wire contract: a two-key camelCase object with both values as
        // strings. A future refactor that silently renamed a field, added a new one, or changed
        // a value type from string to object would trip this assertion — and would silently
        // break any existing sealed URL still in flight.
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);
        let sealed = registration_client
            .seal_open_org_invite_data(sample_input())
            .expect("seal should succeed");

        let json = serde_json::to_value(&sealed).expect("serialize");
        let obj = json.as_object().expect("must be a JSON object");
        assert_eq!(obj.len(), 2, "no extra or missing fields");
        assert!(
            obj.get("sealedData")
                .expect("sealedData key must be present")
                .is_string(),
            "sealedData must serialize as a JSON string"
        );
        assert!(
            obj.get("highEntropySecret")
                .expect("highEntropySecret key must be present")
                .is_string(),
            "highEntropySecret must serialize as a JSON string"
        );
    }

    #[test]
    fn two_seals_produce_distinct_secrets_and_data() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let first = registration_client
            .seal_open_org_invite_data(sample_input())
            .expect("first seal should succeed");
        let second = registration_client
            .seal_open_org_invite_data(sample_input())
            .expect("second seal should succeed");

        // Per-registration randomness: fresh CEK + fresh HighEntropySecret + fresh HKDF salt.
        // Compare via wire form since the underlying types don't derive PartialEq.
        assert_ne!(
            String::from(first.high_entropy_secret),
            String::from(second.high_entropy_secret)
        );
        assert_ne!(
            String::from(&first.sealed_data),
            String::from(&second.sealed_data)
        );
    }
}
