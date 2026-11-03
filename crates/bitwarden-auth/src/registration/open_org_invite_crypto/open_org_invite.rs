//! `OpenOrgInvite` and its sealed form `SealedOpenOrgInviteData`, and the seal/unseal
//! operations between them. Seal returns the sealed blob paired with a `HighEntropySecret`.

use bitwarden_core::key_management::KeySlotIds;
use bitwarden_crypto::{
    KeyStore,
    safe::{
        DataEnvelope, HighEntropySecret, SecretProtectedKeyEnvelope,
        SecretProtectedKeyEnvelopeNamespace,
    },
};
use serde::{Deserialize, Serialize};

use super::{RegistrationOpenOrgInviteData, data_v1::RegistrationOpenOrgInviteDataV1};
use crate::registration::registration_client::RegistrationError;

/// Byte length of the per-registration [`HighEntropySecret`] the seal path generates.
pub(super) const OPEN_ORG_INVITE_SECRET_SIZE_BYTES: usize = 32;

/// Plaintext open-organization-invite payload. Passed into
/// [`crate::registration::registration_client::RegistrationClient::seal_open_org_invite_data`] to
/// seal to be used in the registration email verification link, and returned by
/// [`crate::registration::registration_client::RegistrationClient::unseal_open_org_invite_data`]
/// for the acceptance flow.
#[bitwarden_ffi::wasm_record]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OpenOrgInvite {
    /// The organization the registrant is joining.
    pub organization_id: String,
    /// The public invite link code carried in the shared invite URL.
    pub invite_link_code: String,
    /// The invite secret associated with the invite link.
    pub invite_secret: String,
}

/// The two sealed envelopes that together carry an open-organization-invite payload.
#[derive(Debug, Clone)]
pub struct SealedOpenOrgInviteData {
    /// The OpenOrgInvite plaintext, encrypted under a fresh CEK.
    pub(super) data_envelope: DataEnvelope,
    /// The CEK, encrypted under the caller's HighEntropySecret.
    pub(super) key_envelope: SecretProtectedKeyEnvelope,
}

// WASM ABI: `SealedOpenOrgInviteData` marshals as its wire string, matching the JSON wire form.
#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type SealedOpenOrgInviteData = Tagged<string, "SealedOpenOrgInviteData">;
"#;

impl SealedOpenOrgInviteData {
    /// Seals an [`OpenOrgInvite`] into a [`SealedOpenOrgInviteData`] plus a freshly generated
    /// [`HighEntropySecret`]. The caller must keep the secret client-side and place the sealed
    /// data on the verification-email link; both halves are required to unseal.
    pub fn seal(input: OpenOrgInvite) -> Result<(Self, HighEntropySecret), RegistrationError> {
        // Per-call KeyStore — CEK never lives beyond this operation.
        let key_store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = key_store.context_mut();

        let high_entropy_secret = HighEntropySecret::make(OPEN_ORG_INVITE_SECRET_SIZE_BYTES)
            .map_err(|_| RegistrationError::Crypto)?;

        let versioned: RegistrationOpenOrgInviteData = RegistrationOpenOrgInviteDataV1 {
            organization_id: input.organization_id,
            invite_link_code: input.invite_link_code,
            invite_secret: input.invite_secret,
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

        Ok((
            SealedOpenOrgInviteData {
                data_envelope,
                key_envelope,
            },
            high_entropy_secret,
        ))
    }

    /// Unseals a [`SealedOpenOrgInviteData`] back into an [`OpenOrgInvite`], given the paired
    /// [`HighEntropySecret`] returned by [`Self::seal`]. Returns [`RegistrationError::Crypto`]
    /// if the secret does not match the sealed payload or the payload has been tampered with.
    pub fn unseal(&self, secret: &HighEntropySecret) -> Result<OpenOrgInvite, RegistrationError> {
        // Per-call KeyStore — CEK never lives beyond this function.
        let key_store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = key_store.context_mut();

        let cek_id = self
            .key_envelope
            .unseal(
                secret,
                SecretProtectedKeyEnvelopeNamespace::RegistrationOpenOrgInvite,
                &mut ctx,
            )
            .map_err(|_| RegistrationError::Crypto)?;

        let versioned: RegistrationOpenOrgInviteData = self
            .data_envelope
            .unseal(cek_id, &mut ctx)
            .map_err(|_| RegistrationError::Crypto)?;

        // No post-decrypt equality check on the plaintext — the AES-GCM auth tag at each
        // envelope layer is the substitution defense.
        let RegistrationOpenOrgInviteData::RegistrationOpenOrgInviteDataV1(v1) = versioned;
        Ok(OpenOrgInvite {
            organization_id: v1.organization_id,
            invite_link_code: v1.invite_link_code,
            invite_secret: v1.invite_secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input() -> OpenOrgInvite {
        OpenOrgInvite {
            organization_id: "1bc9ac1e-f5aa-45f2-94bf-b181009709b8".to_string(),
            invite_link_code: "abcd1234efgh5678".to_string(),
            invite_secret: "raw-invite-secret-material-base64url".to_string(),
        }
    }

    #[test]
    fn seal_produces_populated_sealed_data_and_high_entropy_secret() {
        let (sealed_data, high_entropy_secret) =
            SealedOpenOrgInviteData::seal(sample_input()).expect("seal should succeed");

        let wire = String::from(&sealed_data);
        assert!(!wire.is_empty());
        let parsed: SealedOpenOrgInviteData = wire.parse().expect("wire form must round-trip");
        let _ = parsed.data_envelope;
        let _ = parsed.key_envelope;

        // High-entropy secret should also round-trip via its own wire form.
        let secret_wire = String::from(high_entropy_secret);
        assert!(!secret_wire.is_empty());
        secret_wire
            .parse::<HighEntropySecret>()
            .expect("high_entropy_secret must be a valid wire string");
    }

    #[test]
    fn two_seals_produce_distinct_secrets_and_data() {
        let (first_data, first_secret) =
            SealedOpenOrgInviteData::seal(sample_input()).expect("first seal should succeed");
        let (second_data, second_secret) =
            SealedOpenOrgInviteData::seal(sample_input()).expect("second seal should succeed");

        // Per-registration randomness: fresh CEK + secret + HKDF salt.
        assert_ne!(String::from(first_secret), String::from(second_secret));
        assert_ne!(String::from(&first_data), String::from(&second_data));
    }

    #[test]
    fn seal_unseal_round_trip_recovers_original_fields() {
        let input = sample_input();
        let (sealed_data, high_entropy_secret) =
            SealedOpenOrgInviteData::seal(input.clone()).expect("seal should succeed");

        let unsealed = sealed_data
            .unseal(&high_entropy_secret)
            .expect("unseal should succeed");

        assert_eq!(unsealed, input);
    }

    #[test]
    fn unseal_fails_with_wrong_high_entropy_secret() {
        let (sealed_data, _) =
            SealedOpenOrgInviteData::seal(sample_input()).expect("seal should succeed");
        let unrelated = HighEntropySecret::make(OPEN_ORG_INVITE_SECRET_SIZE_BYTES).unwrap();

        let err = sealed_data
            .unseal(&unrelated)
            .expect_err("unseal must reject an unrelated secret");
        assert!(matches!(err, RegistrationError::Crypto));
    }
}
