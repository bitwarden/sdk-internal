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
use bitwarden_crypto::{KeyStore, safe::SecretProtectedKeyEnvelopeNamespace};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::{
    RegistrationOpenOrgInviteData,
    seal::{OpenOrgInviteSealRequest, SealedOpenOrgInvite},
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
        // Per-call transient key store, matching the seal path — the CEK produced by the outer
        // unseal never lives beyond this function.
        let key_store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = key_store.context_mut();

        let cek_id = sealed
            .sealed_data
            .key_envelope
            .unseal(
                &sealed.high_entropy_secret,
                SecretProtectedKeyEnvelopeNamespace::RegistrationOpenOrgInvite,
                &mut ctx,
            )
            .map_err(|_| RegistrationError::Crypto)?;

        let versioned: RegistrationOpenOrgInviteData = sealed
            .sealed_data
            .data_envelope
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

#[cfg(test)]
mod tests {
    use bitwarden_core::Client;
    use bitwarden_crypto::safe::HighEntropySecret;
    use bitwarden_encoding::B64Url;

    use super::*;
    use crate::registration::open_org_invite::seal::{
        OPEN_ORG_INVITE_SECRET_SIZE_BYTES, SealedEnvelopePair, SealedEnvelopePairError,
    };

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
        sealed.high_entropy_secret =
            HighEntropySecret::make(OPEN_ORG_INVITE_SECRET_SIZE_BYTES).unwrap();

        let err = registration_client
            .unseal_open_org_invite_data(sealed)
            .expect_err("unseal must reject an unrelated secret");
        assert!(matches!(err, RegistrationError::Crypto));
    }

    #[test]
    fn unseal_fails_when_sealed_data_wire_is_truncated_across_round_trip() {
        // Simulate a truncated `sealed_data` blob arriving over the JSON wire: encode the seal
        // output, truncate the sealed-data string, and re-parse. The parse itself should fail
        // at the SealedEnvelopePair layer (CBOR framing broken by truncation).
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);
        let sealed = seal(&registration_client, sample_input());

        let mut wire = String::from(&sealed.sealed_data);
        wire.truncate(wire.len() / 2);

        let err = wire
            .parse::<SealedEnvelopePair>()
            .expect_err("truncated wire must be rejected at parse time");
        assert!(matches!(err, SealedEnvelopePairError::Malformed));
    }

    #[test]
    fn unseal_fails_when_sealed_data_wire_is_malformed_base64url() {
        // Same shape as the truncation test but with an invalid base64url prefix.
        let err = "not-valid-base64url!"
            .parse::<SealedEnvelopePair>()
            .expect_err("malformed base64url must be rejected at parse time");
        assert!(matches!(err, SealedEnvelopePairError::Malformed));

        // Also verify the outer B64Url decoder itself rejects the same input, which is what
        // exercises the pre-CBOR path in the parser.
        assert!(B64Url::try_from("not-valid-base64url!").is_err());
    }

    #[test]
    fn sealed_envelope_pair_parse_rejects_valid_cbor_with_bad_key_envelope_bytes() {
        // Build a well-formed base64url + CBOR wire whose `k` field decodes but does not parse
        // as a `SecretProtectedKeyEnvelope`. Exercises the parse-envelope step (step 4 in the
        // FromStr walkthrough) — the step that base64url/CBOR/truncation tests never reach.
        #[derive(serde::Serialize)]
        struct FakeWire<'a> {
            #[serde(rename = "d", with = "serde_bytes")]
            d: &'a [u8],
            #[serde(rename = "k", with = "serde_bytes")]
            k: &'a [u8],
        }
        let fake = FakeWire {
            d: &[1, 2, 3, 4],       // DataEnvelope::from is an infallible byte-wrap; that's fine
            k: &[0xff, 0xff, 0xff], // won't parse as SecretProtectedKeyEnvelope
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&fake, &mut buf).unwrap();
        let wire = B64Url::from(buf).to_string();

        let err = wire
            .parse::<SealedEnvelopePair>()
            .expect_err("bad key-envelope bytes must be rejected at parse time");
        assert!(matches!(err, SealedEnvelopePairError::Malformed));
    }

    #[test]
    fn seal_json_round_trip_unseal_recovers_original_fields() {
        // The whole point of the typed-fields refactor: `SealedOpenOrgInvite` marshals through
        // serde as strings and unseals identically after a JSON round-trip — the shape a real
        // client would send through the server + URL + query param.
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let input = sample_input();
        let sealed = seal(&registration_client, input.clone());

        let json = serde_json::to_string(&sealed).expect("serialize");
        let round_tripped: SealedOpenOrgInvite = serde_json::from_str(&json).expect("deserialize");

        let unsealed = registration_client
            .unseal_open_org_invite_data(round_tripped)
            .expect("unseal after JSON round-trip should succeed");
        assert_eq!(unsealed, input);
    }
}
