//! Helpers shared by the unit tests. Integration tests keep their own copy in `tests/common`.

use std::sync::LazyLock;

use bitwarden_access_token::{AccessToken, AccessTokenKind, make_access_token_secrets};
use bitwarden_core::{
    OrganizationId,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};
use bitwarden_crypto::{
    BitwardenLegacyKeyBytes, KeyDecryptable, KeyEncryptable, KeyStore, SymmetricCryptoKey,
    SymmetricKeyAlgorithm,
};
use bitwarden_encoding::{B64, B64Url};

/// The organisation every unit test authenticates into.
pub(crate) fn test_org_id() -> OrganizationId {
    "3f1a5c4e-7b2d-4f8a-9c6e-1d2b3a4c5d6e"
        .parse()
        .expect("valid uuid")
}

/// The org slot for [`test_org_id`].
pub(crate) fn test_org_slot() -> SymmetricKeySlotId {
    SymmetricKeySlotId::Organization(test_org_id())
}

/// An access token carrying `organization_id`, shaped like the one the server issues. `tag` lands
/// in the subject claim so two tokens can be told apart; tests asserting on an `Authorization`
/// header build the expected value through this same function. Only the claims segment is real.
pub(crate) fn access_token_tagged(organization_id: OrganizationId, tag: &str) -> String {
    let claims = serde_json::json!({
        "exp": 1_900_000_000u64,
        "sub": tag,
        "scope": ["api.pam.rotation"],
        "organization": organization_id.to_string(),
    });

    let payload = B64Url::from(claims.to_string().as_bytes());
    format!("header.{payload}.signature")
}

/// A real token and its derived key, minted once via `make_access_token_secrets` so the two always
/// agree.
static TEST_CREDENTIAL: LazyLock<(String, SymmetricCryptoKey)> = LazyLock::new(|| {
    let wrapping_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
    let store: KeyStore<KeySlotIds> = KeyStore::default();
    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(test_org_slot(), wrapping_key.clone())
        .expect("set_symmetric_key");

    let secrets = {
        let mut ctx = store.context_mut();
        make_access_token_secrets(&mut ctx, test_org_slot(), AccessTokenKind::AccessConnector)
            .expect("mint secrets")
    };

    // Recover the derived key from the `key` field, as an organization would.
    let derived_key_b64: String = secrets
        .key
        .decrypt_with_key(&wrapping_key)
        .expect("decrypt key field");
    let b64: B64 = derived_key_b64.parse().expect("valid b64");
    let derived_key = SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(&b64))
        .expect("valid derived key");

    let token_str = secrets.into_token(uuid::Uuid::new_v4(), "test-secret");
    (token_str, derived_key)
});

pub(crate) fn test_token() -> AccessToken {
    AccessToken::parse(&TEST_CREDENTIAL.0, AccessTokenKind::AccessConnector).expect("valid token")
}

/// The identity server's `encrypted_payload` for `org_key`, openable by [`test_token`].
pub(crate) fn encrypted_payload_for(org_key: &SymmetricCryptoKey) -> String {
    let org_key_b64 = B64::from(org_key.to_encoded().as_ref());
    format!(r#"{{"encryptionKey":"{org_key_b64}"}}"#)
        .as_str()
        .encrypt_with_key(&TEST_CREDENTIAL.1)
        .expect("encrypt payload")
        .to_string()
}
