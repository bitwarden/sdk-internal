//! Known-answer derivation vectors, and mint/open round trips that don't need a wire format
//! (`bitwarden-access-token` owns the wire-format and end-to-end tests).

use bitwarden_crypto::{
    Decryptable, KeyStore, SymmetricCryptoKey, SymmetricKeyAlgorithm, key_slot_ids,
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
