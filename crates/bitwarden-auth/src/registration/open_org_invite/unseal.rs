//! Unseals a [`SealedOpenOrgInvite`] back into the plaintext [`OpenOrgInviteSealRequest`],
//! provided the caller supplies the paired [`HighEntropySecret`] the seal path returned. This
//! runs on the verification-email tab after registration-finish has logged the user in.
//!
//! Reverses the two-envelope construction documented in [`super::seal`]: outer key envelope →
//! inner CEK, then inner data envelope → plaintext.
//!
//! Any failure — malformed wire, wrong secret, tampered blob, cross-namespace — surfaces as
//! [`RegistrationError::Crypto`]. The SDK performs no post-decrypt equality check on the
//! plaintext; the AES-GCM auth tag at each envelope layer is the substitution defense.

use bitwarden_core::key_management::KeySlotIds;
use bitwarden_crypto::{
    KeyStore,
    safe::{
        DataEnvelope, HighEntropySecret, SecretProtectedKeyEnvelope,
        SecretProtectedKeyEnvelopeNamespace,
    },
};
use bitwarden_encoding::B64Url;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::{
    RegistrationOpenOrgInviteData,
    seal::{OpenOrgInviteSealRequest, SealedEnvelopePair, SealedOpenOrgInvite},
};
use crate::registration::registration_client::{RegistrationClient, RegistrationError};

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl RegistrationClient {
    /// Unseals a [`SealedOpenOrgInvite`] back into an [`OpenOrgInviteSealRequest`]. Returns
    /// [`RegistrationError::Crypto`] if the sealed payload or the paired secret is malformed,
    /// mismatched, or tampered with.
    pub fn unseal_open_org_invite_data(
        &self,
        sealed: SealedOpenOrgInvite,
    ) -> Result<OpenOrgInviteSealRequest, RegistrationError> {
        let (data_envelope, key_envelope) = split_envelopes(&sealed.sealed_data)?;
        let high_entropy_secret = HighEntropySecret::from_base64(&sealed.high_entropy_secret)
            .map_err(|_| RegistrationError::Crypto)?;

        // Per-call transient key store, matching the seal path — the CEK produced by the outer
        // unseal never lives beyond this function.
        let key_store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = key_store.context_mut();

        let cek_id = key_envelope
            .unseal(
                &high_entropy_secret,
                SecretProtectedKeyEnvelopeNamespace::RegistrationOpenOrgInvite,
                &mut ctx,
            )
            .map_err(|_| RegistrationError::Crypto)?;

        let versioned: RegistrationOpenOrgInviteData = data_envelope
            .unseal(cek_id, &mut ctx)
            .map_err(|_| RegistrationError::Crypto)?;

        let RegistrationOpenOrgInviteData::RegistrationOpenOrgInviteDataV1(v1) = versioned;
        Ok(OpenOrgInviteSealRequest {
            organization_id: v1.organization_id,
            invite_link_code: v1.invite_link_code,
            invite_key: v1.invite_key,
        })
    }
}

/// Reverses [`super::seal::combine_envelopes`]: base64url-decode, CBOR-decode, split into the two
/// typed envelopes. Any framing error surfaces as [`RegistrationError::Crypto`] per the AC that
/// malformed input never panics and never silently returns empty.
fn split_envelopes(
    sealed_data: &str,
) -> Result<(DataEnvelope, SecretProtectedKeyEnvelope), RegistrationError> {
    let outer = B64Url::try_from(sealed_data).map_err(|_| RegistrationError::Crypto)?;
    let pair: SealedEnvelopePair =
        ciborium::de::from_reader(outer.as_bytes()).map_err(|_| RegistrationError::Crypto)?;

    let data_envelope = DataEnvelope::from(pair.data_envelope);
    let key_envelope = SecretProtectedKeyEnvelope::try_from(&pair.key_envelope)
        .map_err(|_| RegistrationError::Crypto)?;
    Ok((data_envelope, key_envelope))
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

    fn seal(client: &RegistrationClient, input: OpenOrgInviteSealRequest) -> SealedOpenOrgInvite {
        client
            .seal_open_org_invite_data(input)
            .expect("seal should succeed")
    }

    #[test]
    fn seal_unseal_round_trip_recovers_original_fields() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let input = sample_input();
        let sealed = seal(&registration_client, input.clone());
        let unsealed = registration_client
            .unseal_open_org_invite_data(sealed)
            .expect("unseal should succeed");

        assert_eq!(unsealed, input);
    }

    #[test]
    fn unseal_fails_with_wrong_high_entropy_secret() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let mut sealed = seal(&registration_client, sample_input());
        let unrelated = HighEntropySecret::make(32).unwrap().to_base64();
        sealed.high_entropy_secret = unrelated;

        let err = registration_client
            .unseal_open_org_invite_data(sealed)
            .expect_err("unseal must reject an unrelated secret");
        assert!(matches!(err, RegistrationError::Crypto));
    }

    #[test]
    fn unseal_fails_when_high_entropy_secret_is_malformed_base64() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let mut sealed = seal(&registration_client, sample_input());
        sealed.high_entropy_secret = "!!!not-base64!!!".to_string();

        let err = registration_client
            .unseal_open_org_invite_data(sealed)
            .expect_err("unseal must reject malformed base64 for the secret");
        assert!(matches!(err, RegistrationError::Crypto));
    }

    #[test]
    fn unseal_fails_when_sealed_data_is_malformed_base64url() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let mut sealed = seal(&registration_client, sample_input());
        sealed.sealed_data = "not-valid-base64url!".to_string();

        let err = registration_client
            .unseal_open_org_invite_data(sealed)
            .expect_err("unseal must reject malformed sealed_data at the split step");
        assert!(matches!(err, RegistrationError::Crypto));
    }

    #[test]
    fn unseal_fails_when_sealed_data_is_truncated() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let mut sealed = seal(&registration_client, sample_input());
        // Drop the tail — the base64url still parses but the CBOR framing collapses.
        sealed.sealed_data.truncate(sealed.sealed_data.len() / 2);

        let err = registration_client
            .unseal_open_org_invite_data(sealed)
            .expect_err("unseal must reject truncated sealed_data");
        assert!(matches!(err, RegistrationError::Crypto));
    }
}
