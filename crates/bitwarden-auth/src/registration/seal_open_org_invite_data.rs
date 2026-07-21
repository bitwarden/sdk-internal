//! Seals an open-organization-invite context into an opaque wire artifact plus a paired
//! [`HighEntropySecret`]. The sealed data rides the verification email URL; the secret stays
//! client-side. Both are needed to recover the original invite context via
//! [`super::unseal_open_org_invite_data`].
//!
//! Two-envelope construction mirrors the pattern in
//! `bitwarden-organization-crypto/src/invite_key_bundle.rs`:
//! - inner [`DataEnvelope`] seals the [`RegistrationOpenOrgInviteData`] payload with a freshly
//!   generated content-encryption key (CEK);
//! - outer [`SecretProtectedKeyEnvelope`] seals that CEK with a per-registration
//!   [`HighEntropySecret`].
//!
//! Substitution defense at both layers is the AES-GCM auth tag / wrong-key check — the SDK
//! performs no post-decrypt equality check on the plaintext, matching how
//! `Invite::unseal` in `invite_key_bundle` trusts the crypto.

use bitwarden_core::{Client, key_management::KeySlotIds};
use bitwarden_crypto::{
    KeyStore,
    safe::{
        DataEnvelope, HighEntropySecret, SecretProtectedKeyEnvelope,
        SecretProtectedKeyEnvelopeNamespace,
    },
};
use bitwarden_encoding::B64Url;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::{
    open_org_invite_data::{RegistrationOpenOrgInviteData, RegistrationOpenOrgInviteDataV1},
    registration_client::{RegistrationClient, RegistrationError},
};

/// The plaintext invite context that a registrant will consume on the verification-email tab to
/// complete the open-organization-invite acceptance. All three fields are required.
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct OpenOrgInviteData {
    /// The organization the registrant is joining.
    pub organization_id: String,
    /// The public invite link code (also carried in the shared invite URL).
    pub invite_link_code: String,
    /// The invite key associated with the invite link. Never leaves the client except in
    /// pre-sealed form.
    pub invite_key: String,
}

/// The output of [`RegistrationClient::seal_open_org_invite_data`]. Both fields are opaque wire
/// artifacts safe to transport at layer boundaries; both are needed to unseal.
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SealedOpenOrgInvite {
    /// Base64url-encoded CBOR wrapper containing the inner data envelope and outer key envelope.
    /// Rides the verification email URL as an opaque blob.
    pub sealed_data: String,
    /// Standardized base64 of the per-registration [`HighEntropySecret`]. Stays client-side
    /// (e.g. `localStorage`) — never sent to the server.
    pub high_entropy_secret: String,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl RegistrationClient {
    /// Seals an open-organization-invite context so the registrant can carry it across the
    /// verification-email tab boundary. Returns both halves — the sealed data (server-visible)
    /// and the paired high-entropy secret (client-only). See module-level docs for the
    /// two-envelope construction.
    pub fn seal_open_org_invite_data(
        &self,
        input: OpenOrgInviteData,
    ) -> Result<SealedOpenOrgInvite, RegistrationError> {
        internal_seal_open_org_invite_data(&self.client, input)
    }
}

fn internal_seal_open_org_invite_data(
    _client: &Client,
    input: OpenOrgInviteData,
) -> Result<SealedOpenOrgInvite, RegistrationError> {
    // The CEK is transient and never persists across calls. A per-call `KeyStore` keeps the
    // key material scoped to this operation so nothing lingers in the caller's key store.
    let key_store: KeyStore<KeySlotIds> = KeyStore::default();
    let mut ctx = key_store.context_mut();

    let high_entropy_secret = HighEntropySecret::make(32).map_err(|_| RegistrationError::Crypto)?;

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

    let sealed_data = combine_envelopes(&data_envelope, &key_envelope)?;

    Ok(SealedOpenOrgInvite {
        sealed_data,
        high_entropy_secret: high_entropy_secret.to_base64(),
    })
}

/// Internal CBOR wire schema for `sealed_data`. Byte arrays are the direct serializations of the
/// respective envelope types (CBOR handles them as `bstr` natively), avoiding the
/// double-base64 overhead of nesting the envelopes' own string forms.
#[derive(Serialize, Deserialize)]
pub(super) struct SealedEnvelopePair {
    #[serde(rename = "d")]
    pub(super) data_envelope: Vec<u8>,
    #[serde(rename = "k")]
    pub(super) key_envelope: Vec<u8>,
}

/// CBOR-encodes the two envelopes and outer-base64url-encodes the result. Base64url keeps the
/// output URL-safe, since the sealed data rides the verification email URL fragment.
pub(super) fn combine_envelopes(
    data_envelope: &DataEnvelope,
    key_envelope: &SecretProtectedKeyEnvelope,
) -> Result<String, RegistrationError> {
    let pair = SealedEnvelopePair {
        data_envelope: data_envelope.into(),
        key_envelope: key_envelope.into(),
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&pair, &mut buf).map_err(|_| RegistrationError::Crypto)?;
    Ok(B64Url::from(buf).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input() -> OpenOrgInviteData {
        OpenOrgInviteData {
            organization_id: "1bc9ac1e-f5aa-45f2-94bf-b181009709b8".to_string(),
            invite_link_code: "abcd1234efgh5678".to_string(),
            invite_key: "raw-invite-key-material-base64url".to_string(),
        }
    }

    #[test]
    fn seal_returns_non_empty_sealed_data_and_high_entropy_secret() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let sealed = registration_client
            .seal_open_org_invite_data(sample_input())
            .expect("seal should succeed");

        assert!(!sealed.sealed_data.is_empty());
        assert!(!sealed.high_entropy_secret.is_empty());
    }

    #[test]
    fn seal_sealed_data_is_valid_base64url() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let sealed = registration_client
            .seal_open_org_invite_data(sample_input())
            .expect("seal should succeed");

        // Wire-format sanity: sealed_data must decode as base64url and re-encode identically.
        let decoded = B64Url::try_from(sealed.sealed_data.as_str())
            .expect("sealed_data must be valid base64url");
        assert_eq!(
            B64Url::from(decoded.as_bytes()).to_string(),
            sealed.sealed_data
        );
    }

    #[test]
    fn seal_high_entropy_secret_is_valid_base64() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let sealed = registration_client
            .seal_open_org_invite_data(sample_input())
            .expect("seal should succeed");

        // The secret must be a HighEntropySecret round-trippable base64 string.
        HighEntropySecret::from_base64(&sealed.high_entropy_secret)
            .expect("high_entropy_secret must be valid base64");
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
        assert_ne!(first.high_entropy_secret, second.high_entropy_secret);
        assert_ne!(first.sealed_data, second.sealed_data);
    }
}
