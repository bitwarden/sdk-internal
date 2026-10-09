//! Known-answer derivation vectors, and mint/open round trips that don't need a wire format
//! (`bitwarden-access-token` owns the wire-format and end-to-end tests).

use bitwarden_crypto::{
    Decryptable, EncString, KeyStore, SymmetricCryptoKey, SymmetricKeyAlgorithm, key_slot_ids,
};
use bitwarden_encoding::B64;

use crate::{
    AccessTokenError, AccessTokenKey, AccessTokenSeed, KeyPurpose, make_access_token_key_material,
};

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

fn store_with_org_key() -> (KeyStore<TestKeySlotIds>, SymmetricCryptoKey) {
    let store: KeyStore<TestKeySlotIds> = KeyStore::default();
    let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);

    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(TestSymmSlotId::Organization, org_key.clone())
        .expect("set_symmetric_key");

    (store, org_key)
}

/// The seed from the shared access-token test vector (base64 `X8vbvA0bduihIDe/qrzIQQ==`), also used
/// by `bitwarden-access-token`'s own wire-format known-answer tests.
fn kat_seed() -> AccessTokenSeed {
    let b64: B64 = "X8vbvA0bduihIDe/qrzIQQ==".parse().expect("valid base64");
    AccessTokenSeed::try_from(b64.as_bytes()).expect("16 bytes")
}

/// Known-answer derived key for [`kat_seed`] under `KeyPurpose::new("sm-access-token")`. Must stay
/// byte-identical with the web vault and `bitwarden-core`'s existing Secrets Manager access tokens.
const EXPECTED_SM_KEY_B64: &str =
    "H9/oIRLtL9nGCQOVDjSMoEbJsjWXSOCb3qeyDt6ckzS3FhyboEDWyTP/CQfbIszNmAVg2ExFganG1FVFGXO/Jg==";

/// Known-answer derived key for [`kat_seed`] under `KeyPurpose::new("access-connector")`. Differs
/// from [`EXPECTED_SM_KEY_B64`] even though both share the same seed, because the two purposes
/// derive with different HKDF info.
const EXPECTED_ACCESS_CONNECTOR_KEY_B64: &str =
    "wshEbn7hhFOElbmxzNR4tpotgxjXhowvZH7xSbcpz03yV2cZmNE2/bdkhbzObwt7+mK/oHm+sryfUCXHe1N8pw==";

#[test]
fn sm_purpose_matches_the_known_answer() {
    let key = AccessTokenKey::derive(&kat_seed(), KeyPurpose::new("sm-access-token"));
    assert_eq!(key.to_base64_for_tests(), EXPECTED_SM_KEY_B64);
}

#[test]
fn access_connector_purpose_matches_the_known_answer() {
    let key = AccessTokenKey::derive(&kat_seed(), KeyPurpose::new("access-connector"));
    assert_eq!(key.to_base64_for_tests(), EXPECTED_ACCESS_CONNECTOR_KEY_B64);
}

/// Confirms the purpose actually separates key spaces rather than both collapsing onto the shared
/// `DERIVE_NAME` salt.
#[test]
fn same_seed_different_purpose_yields_different_keys() {
    let seed = kat_seed();
    let sm_key = AccessTokenKey::derive(&seed, KeyPurpose::new("sm-access-token"));
    let ac_key = AccessTokenKey::derive(&seed, KeyPurpose::new("access-connector"));
    assert_ne!(sm_key.to_base64_for_tests(), ac_key.to_base64_for_tests());
}

/// A holder with nothing but the seed and the purpose re-derives the key and opens
/// `encrypted_payload` to recover the organization key. No wire format involved.
#[test]
fn mint_then_open_round_trip() {
    let (issuer_store, org_key) = store_with_org_key();
    let purpose = KeyPurpose::new("test-purpose");

    let material = {
        let mut ctx = issuer_store.context_mut();
        make_access_token_key_material(&mut ctx, TestSymmSlotId::Organization, purpose)
            .expect("mint key material")
    };
    let encrypted_payload = material.encrypted_payload.to_string();
    let seed = material.into_seed();

    let holder_key = AccessTokenKey::derive(&seed, purpose);

    let holder_store: KeyStore<TestKeySlotIds> = KeyStore::default();
    let mut ctx = holder_store.context_mut();
    holder_key
        .open_payload(&mut ctx, &encrypted_payload, TestSymmSlotId::Organization)
        .expect("open_payload");

    #[allow(deprecated)]
    let recovered = ctx
        .dangerous_get_symmetric_key(TestSymmSlotId::Organization)
        .expect("the slot was just populated");
    assert_eq!(
        recovered.to_base64().to_string(),
        org_key.to_base64().to_string(),
        "the holder must recover the organization key verbatim"
    );
}

/// The `key` field is not read by `open_payload`, so a mistake in it would go unnoticed until an
/// organization-key rotation.
#[test]
fn the_key_field_wraps_the_same_key_the_holder_derives() {
    let (issuer_store, _org_key) = store_with_org_key();
    let purpose = KeyPurpose::new("test-purpose");

    let material = {
        let mut ctx = issuer_store.context_mut();
        make_access_token_key_material(&mut ctx, TestSymmSlotId::Organization, purpose)
            .expect("mint key material")
    };
    let key_field = material.key.clone();
    let seed = material.into_seed();

    let mut ctx = issuer_store.context();
    let wrapped: String = key_field
        .decrypt(&mut ctx, TestSymmSlotId::Organization)
        .expect("the org key unwraps the key field");

    let holder_key = AccessTokenKey::derive(&seed, purpose);
    assert_eq!(
        wrapped,
        holder_key.to_base64_for_tests(),
        "the key field must hold the same derived key the holder derives"
    );
}

/// Each registration must mint fresh material, or two holders would share a key and revoking one
/// would not lock out the other.
#[test]
fn each_mint_generates_a_distinct_seed() {
    let (issuer_store, _org_key) = store_with_org_key();
    let purpose = KeyPurpose::new("test-purpose");

    let mint_seed = || {
        let mut ctx = issuer_store.context_mut();
        make_access_token_key_material(&mut ctx, TestSymmSlotId::Organization, purpose)
            .expect("mint key material")
            .into_seed()
    };

    assert_ne!(mint_seed().as_bytes(), mint_seed().as_bytes());
}

#[test]
fn opening_a_malformed_payload_is_invalid_payload() {
    let key = AccessTokenKey::derive(&kat_seed(), KeyPurpose::new("test-purpose"));
    let store: KeyStore<TestKeySlotIds> = KeyStore::default();
    let mut ctx = store.context_mut();

    let result = key.open_payload(&mut ctx, "not-an-enc-string", TestSymmSlotId::Organization);
    assert!(matches!(result, Err(AccessTokenError::InvalidPayload)));
}

/// A payload that decrypts fine but whose `encryptionKey` is not a valid key length must be
/// rejected distinctly from a payload that fails to decrypt at all.
#[test]
fn opening_a_payload_with_an_invalid_org_key_is_invalid_org_key() {
    use bitwarden_crypto::PrimitiveEncryptable;

    let seed = kat_seed();
    let purpose = KeyPurpose::new("test-purpose");

    let store: KeyStore<TestKeySlotIds> = KeyStore::default();
    let mut ctx = store.context_mut();
    let derived_key_id = ctx
        .derive_shareable_key(
            zeroize::Zeroizing::new(*seed.as_bytes()),
            crate::key::DERIVE_NAME,
            Some(purpose.as_str()),
        )
        .expect("derive");

    let bad_key_b64 = B64::from(b"too-short".as_slice()).to_string();
    let payload = serde_json::json!({ "encryptionKey": bad_key_b64 });
    let encrypted_payload = payload
        .to_string()
        .encrypt(&mut ctx, derived_key_id)
        .expect("encrypt")
        .to_string();

    let key = AccessTokenKey::derive(&seed, purpose);
    let result = key.open_payload(&mut ctx, &encrypted_payload, TestSymmSlotId::Organization);
    assert!(matches!(result, Err(AccessTokenError::InvalidOrgKey)));
}

/// The `encrypted_payload` from `bitwarden-sm`'s mocked access-token login fixture
/// (`bitwarden_license/bitwarden-sm/src/client_secrets.rs`, `test_access_token_login`), issued for
/// access token `0.ec2c1d46-...:X8vbvA0bduihIDe/qrzIQQ==`, whose seed is [`kat_seed`]. Minted
/// outside this crate: pinning it guards compatibility with Secrets Manager payloads that already
/// exist.
const SM_ENCRYPTED_PAYLOAD: &str = "2.E9fE8+M/VWMfhhim1KlCbQ==|eLsHR484S/tJbIkM6spnG/HP65tj9A6Tba7kAAvUp+rYuQmGLixiOCfMsqt5OvBctDfvvr/AesBu7cZimPLyOEhqEAjn52jF0eaI38XZfeOG2VJl0LOf60Wkfh3ryAMvfvLj3G4ZCNYU8sNgoC2+IQ==|lNApuCQ4Pyakfo/wwuuajWNaEX/2MW8/3rjXB/V7n+k=";

/// The secret `key` field from the same fixture, wrapped under the organization key that
/// [`SM_ENCRYPTED_PAYLOAD`] carries. Decrypting it with the org key recovered from the payload is
/// an independent check that the pinned org key is the real one.
const SM_SECRET_KEY_FIELD: &str = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";

/// Known-answer organization key recovered from [`SM_ENCRYPTED_PAYLOAD`]. Must stay byte-identical
/// so existing Secrets Manager access tokens keep opening.
const EXPECTED_SM_ORG_KEY_B64: &str =
    "k/6PcwG7Hm/eZfvvOvP6EqGx1JKgbzYrWwpOIHsxbJHQMpIMg5Ud94AQHduSR+XMMaFiSB+nszbO4JPXj04YwA==";

/// Opens the real Secrets Manager fixture payload, checks the recovered org key against the
/// pinned known answer, then uses that recovered key to decrypt the fixture's own secret `key`
/// field, as an independent check that the pinned org key is the real one.
#[test]
fn sm_fixture_payload_opens_to_the_known_org_key() {
    let key = AccessTokenKey::derive(&kat_seed(), KeyPurpose::new("sm-access-token"));
    let store: KeyStore<TestKeySlotIds> = KeyStore::default();
    let mut ctx = store.context_mut();
    key.open_payload(&mut ctx, SM_ENCRYPTED_PAYLOAD, TestSymmSlotId::Organization)
        .expect("open_payload");

    #[allow(deprecated)]
    let org_key = ctx
        .dangerous_get_symmetric_key(TestSymmSlotId::Organization)
        .expect("the slot was just populated");
    assert_eq!(org_key.to_base64().to_string(), EXPECTED_SM_ORG_KEY_B64);

    let secret_key: EncString = SM_SECRET_KEY_FIELD.parse().expect("valid enc string");
    let _: Vec<u8> = secret_key
        .decrypt(&mut ctx, TestSymmSlotId::Organization)
        .expect("the recovered org key must decrypt the fixture's own secret key field");
}

/// Opening the SM fixture payload with a key derived under the wrong purpose must fail the same
/// way as any other undecryptable payload. An HMAC/integrity failure is not evidence about the
/// shape of the org key, so it must not be reported as [`AccessTokenError::InvalidOrgKey`].
#[test]
fn opening_the_sm_payload_with_the_wrong_purpose_is_invalid_payload() {
    let key = AccessTokenKey::derive(&kat_seed(), KeyPurpose::new("access-connector"));
    let store: KeyStore<TestKeySlotIds> = KeyStore::default();
    let mut ctx = store.context_mut();

    let result = key.open_payload(&mut ctx, SM_ENCRYPTED_PAYLOAD, TestSymmSlotId::Organization);
    assert!(matches!(result, Err(AccessTokenError::InvalidPayload)));
}

/// A payload that decrypts fine but whose JSON has no `encryptionKey` field at all (as opposed to
/// an invalid value for it) must also be `InvalidPayload`, not a panic.
#[test]
fn opening_a_payload_missing_the_encryption_key_field_is_invalid_payload() {
    use bitwarden_crypto::PrimitiveEncryptable;

    let seed = kat_seed();
    let purpose = KeyPurpose::new("test-purpose");

    let store: KeyStore<TestKeySlotIds> = KeyStore::default();
    let mut ctx = store.context_mut();
    let derived_key_id = ctx
        .derive_shareable_key(
            zeroize::Zeroizing::new(*seed.as_bytes()),
            crate::key::DERIVE_NAME,
            Some(purpose.as_str()),
        )
        .expect("derive");

    let payload = serde_json::json!({ "other": "x" });
    let encrypted_payload = payload
        .to_string()
        .encrypt(&mut ctx, derived_key_id)
        .expect("encrypt")
        .to_string();

    let key = AccessTokenKey::derive(&seed, purpose);
    let result = key.open_payload(&mut ctx, &encrypted_payload, TestSymmSlotId::Organization);
    assert!(matches!(result, Err(AccessTokenError::InvalidPayload)));
}

/// Test-only organization key for the access-connector mint vector below. Minted with
/// `make_access_token_key_material` under `KeyPurpose::new("access-connector")`; pins the mint ->
/// payload -> organization `key` field chain against silent format drift.
const AC_VECTOR_ORG_KEY_B64: &str =
    "TrSlqL7yg60LxC/kSlJNm1kZft+Fn97ArZsQovYW5QfbT6kbDVdfuFQ7U3LjMkNoAB9uFveLknMyG0ydLwonvA==";

/// The seed [`AC_VECTOR_ENCRYPTED_PAYLOAD`] and [`AC_VECTOR_KEY_FIELD`] were derived from.
const AC_VECTOR_SEED_B64: &str = "BUZui++P5b13mtPE449l3w==";

/// Wraps [`AC_VECTOR_ORG_KEY_B64`] for the token holder, under the key derived from
/// [`AC_VECTOR_SEED_B64`] with `KeyPurpose::new("access-connector")`.
const AC_VECTOR_ENCRYPTED_PAYLOAD: &str = "2.KjJM6/okJQ9y24YBkmpVhA==|sjd7f9EI71ms4KObPPguOq12i4N6pAWXEnx26OkakGtrlfuUE3n2vBxa2xRgiYaOUK9oab1Uynyu7MzVomLcURMbx6U3yCwTVp/qM9IGoYAyN6eQmvYWy0Lvuhu7e9MMS5phuLiDXZhJ3mLJURuRtA==|qA78dKE6e0Tilt9J/IjPa6rCihe0xluF8DjzcvuMydk=";

/// Wraps the derived key's base64 for the organization, under [`AC_VECTOR_ORG_KEY_B64`].
const AC_VECTOR_KEY_FIELD: &str = "2.uFkzZ1ag3XyyRIvBhKcBmw==|igA/FMic6Og6EGShX7/mqYPXMFvPXFDhz7edBu756qGnAG7Blsj9IWpw3v50YU19eYjrVQkDzcj5+qtcRz0s6EGJqljKLlxBMuHZjzck5/YLZXy0d+mmG95D2TzE5Tow|niALH4lGq8SpgkP1CSZl+fbUo8gkbegxPkF2Odx+S+c=";

/// Re-deriving from the pinned seed and purpose must still open the pinned payload to the pinned
/// org key, i.e. the access-connector mint format has not silently changed.
#[test]
fn access_connector_vector_payload_opens_to_the_pinned_org_key() {
    let seed_b64: B64 = AC_VECTOR_SEED_B64.parse().expect("valid base64");
    let seed = AccessTokenSeed::try_from(seed_b64.as_bytes()).expect("16 bytes");
    let key = AccessTokenKey::derive(&seed, KeyPurpose::new("access-connector"));

    let store: KeyStore<TestKeySlotIds> = KeyStore::default();
    let mut ctx = store.context_mut();
    key.open_payload(
        &mut ctx,
        AC_VECTOR_ENCRYPTED_PAYLOAD,
        TestSymmSlotId::Organization,
    )
    .expect("open_payload");

    #[allow(deprecated)]
    let org_key = ctx
        .dangerous_get_symmetric_key(TestSymmSlotId::Organization)
        .expect("the slot was just populated");
    assert_eq!(org_key.to_base64().to_string(), AC_VECTOR_ORG_KEY_B64);
}

/// The organization-side `key` field must still unwrap, under the pinned org key, to the same
/// derived key a holder re-derives from the pinned seed and purpose.
#[test]
fn access_connector_vector_key_field_matches_the_rederived_key() {
    let seed_b64: B64 = AC_VECTOR_SEED_B64.parse().expect("valid base64");
    let seed = AccessTokenSeed::try_from(seed_b64.as_bytes()).expect("16 bytes");

    let org_key_b64: B64 = AC_VECTOR_ORG_KEY_B64.parse().expect("valid base64");
    let org_key = SymmetricCryptoKey::try_from(org_key_b64).expect("valid key");

    let store: KeyStore<TestKeySlotIds> = KeyStore::default();
    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(TestSymmSlotId::Organization, org_key)
        .expect("set_symmetric_key");

    let key_field: EncString = AC_VECTOR_KEY_FIELD.parse().expect("valid enc string");
    let mut ctx = store.context();
    let wrapped: String = key_field
        .decrypt(&mut ctx, TestSymmSlotId::Organization)
        .expect("the org key unwraps the key field");

    let holder_key = AccessTokenKey::derive(&seed, KeyPurpose::new("access-connector"));
    assert_eq!(wrapped, holder_key.to_base64_for_tests());
}
