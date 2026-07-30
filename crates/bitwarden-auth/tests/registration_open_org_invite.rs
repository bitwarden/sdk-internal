//! Integration tests for the open-org-invite registration crossing — public API only.

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
const TEST_VECTOR_SEALED_JSON: &str = "{\"sealedData\":\"omFkWQEIg1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUHP2JYxlt7tDr1P2p4K_W446AAE4gQI6AAE4gAOhBUz0QLrresgFvPHv45VYrcsnCWe2bRkIQIJYFd--cqcLibGDixkdYrJJkYauKwJdaUcq5yK_xrruwJajT6s7UBhtDczVdrEWhtcshb6p_9PoGoKpb9ffUdyqbLumOFGJvUoMcDi9-welLjJ_AX4Qu16ITBDs2Q5KiN3iuVU9N9JEYjgyRHxccpoVuIc3yPFyDIsYcQ0KFmBRpDw50KhYD-G4Tb19QaMfaHEWK83OMIDvmea2FSQOU1SpUbvJYWtYs4RYKKUBAwMYZToAARVcUHP2JYxlt7tDr1P2p4K_W446AAE4gQY6AAE4gAOhBUy6jePlDBaQIzt_vDdYTQiINL9v4KZ077Nf657IAAH7FsyuG9JiCQrID904q7yJGcJYJEYAu9CvKz2ts-oVAjOUu3evNyxqCU2zM2tlwaGqjSET1A1WACmazG3KgYNAogEpM1gg8Ayj9aREd1n-rEPoj97Crrm6DZ1nADBMjLJeAO32VAz2\",\"highEntropySecret\":\"/oeYS4R7k3lWzqtMkydiZlWWK0M5Nkj3qU1I0/k/1YU=\"}";

fn sample_input() -> OpenOrgInvite {
    OpenOrgInvite {
        organization_id: "1bc9ac1e-f5aa-45f2-94bf-b181009709b8".to_string(),
        invite_link_code: "abcd1234efgh5678".to_string(),
        invite_secret: "raw-invite-secret-material-base64url".to_string(),
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
