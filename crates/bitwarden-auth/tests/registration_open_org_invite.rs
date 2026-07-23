//! Integration tests for the open-organization-invite registration crossing.
//!
//! Exercises the crate's public API only (`Client::auth_new().registration()`), so a break here
//! implies a break in what external consumers actually see. Round-trip and JSON-wire round-trip
//! are the two paths a real client (web app) traverses in production.

use bitwarden_auth::{
    AuthClientExt,
    registration::{OpenOrgInvite, RegistrationError, SealedOpenOrgInvite},
};
use bitwarden_core::Client;
use bitwarden_crypto::safe::HighEntropySecret;

/// Pinned JSON wire vector: a `SealedOpenOrgInvite` produced by sealing [`sample_input`] with a
/// specific paired `HighEntropySecret`. Guards backward compatibility of the wire format — a
/// break here means the on-disk / on-URL form of sealed data has changed, which would break any
/// sealed URL already in flight.
///
/// Regenerate manually only if the format is being intentionally rev'd (add a new pinned vector
/// alongside; don't replace this one).
const TEST_VECTOR_SEALED_JSON: &str = "{\"sealedData\":\"omFkWQECg1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUNRvG46j66E9mStKyv2V4gI6AAE4gQI6AAE4gAKhBUx34gcQMaUHA1O5E2BYp8wkVQf1mt_NcUTsUg1RsOsbt9QOXthf1OL0anpQBC-VHJmOvhpLlsift2LQvy9kvdvJEAICf4jBbIhcrKgVB3ByOyUF0WBcmyiSUO-4r_RXOii60QrCoyYPyXR-HWFYfH_K8vOfNNNJ7F95JQZwdzCmfECftFK1T_utF9R9gi85A4NFDKLaMQC_7vQ-6BNy5ZUY0v3HlZEumrh6qq7I9k2Wy0yFnAHWYWtYs4RYKKUBAwMYZToAARVcUNRvG46j66E9mStKyv2V4gI6AAE4gQY6AAE4gAOhBUy4OSguxO7pY5c0SXBYTfmkyD9Kt5JIDfr9M7z1LDMK8xyeXsOx9JSbJysInccqzzhPFX-C6AEulM3em4E3y2M25qD_zYHB1bPTSwEXpt3xJF3BIhntjqnKra0ggYNAogEpM1ggucjwg1hoHBPTx-9hCLC6Ah40TxFTS8fKDQRbEjbn_7L2\",\"highEntropySecret\":\"CX54883hTfRI9oADLOvsVPuao4LT8w6dyIB7ZdkVxqQ=\"}";

fn sample_input() -> OpenOrgInvite {
    OpenOrgInvite {
        organization_id: "1bc9ac1e-f5aa-45f2-94bf-b181009709b8".to_string(),
        invite_link_code: "abcd1234efgh5678".to_string(),
        invite_key: "raw-invite-key-material-base64url".to_string(),
    }
}

#[test]
fn seal_unseal_round_trip_via_public_api() {
    let client = Client::new(None);
    let registration = client.auth_new().registration();

    let input = sample_input();
    let sealed = registration
        .seal_open_org_invite_data(input.clone())
        .expect("seal should succeed");

    let unsealed = registration
        .unseal_open_org_invite_data(sealed)
        .expect("unseal should succeed");

    assert_eq!(unsealed, input);
}

#[test]
fn pinned_wire_vector_unseals_to_expected_plaintext() {
    // Wire format lock-in: deserializing the pinned JSON vector via the public API must always
    // produce the exact plaintext it was sealed from. If this fails, the on-disk/on-URL form
    // has changed and existing sealed URLs would no longer unseal.
    let client = Client::new(None);
    let registration = client.auth_new().registration();

    let sealed: SealedOpenOrgInvite =
        serde_json::from_str(TEST_VECTOR_SEALED_JSON).expect("pinned vector must deserialize");
    let unsealed = registration
        .unseal_open_org_invite_data(sealed)
        .expect("pinned vector must unseal");

    assert_eq!(unsealed, sample_input());
}

#[test]
fn unseal_with_wrong_secret_returns_crypto_error_via_public_api() {
    // Locks the public error contract: an unseal call with a mismatched high-entropy secret
    // surfaces as `RegistrationError::Crypto`, not a panic or a different variant. A future
    // refactor that swallowed the auth-tag failure or remapped it to a different error would
    // fail this test.
    //
    // Size 32 matches what the seal path generates, though any size ≥ MIN_SECRET_LENGTH works
    // here — the mismatch is what drives the failure, not the size.
    let client = Client::new(None);
    let registration = client.auth_new().registration();

    let mut sealed = registration
        .seal_open_org_invite_data(sample_input())
        .expect("seal should succeed");
    sealed.high_entropy_secret = HighEntropySecret::make(32).expect("fresh secret");

    let err = registration
        .unseal_open_org_invite_data(sealed)
        .expect_err("unseal must reject a mismatched secret");
    assert!(matches!(err, RegistrationError::Crypto));
}

#[test]
fn seal_json_round_trip_unseal_via_public_api() {
    // Mirrors the production path: the client seals, ships the JSON through the server + URL,
    // and Tab B deserializes back to `SealedOpenOrgInvite` before unsealing.
    let client = Client::new(None);
    let registration = client.auth_new().registration();

    let input = sample_input();
    let sealed = registration
        .seal_open_org_invite_data(input.clone())
        .expect("seal should succeed");

    let wire_json = serde_json::to_string(&sealed).expect("serialize");
    let round_tripped: SealedOpenOrgInvite = serde_json::from_str(&wire_json).expect("deserialize");

    let unsealed = registration
        .unseal_open_org_invite_data(round_tripped)
        .expect("unseal after JSON round-trip should succeed");

    assert_eq!(unsealed, input);
}
