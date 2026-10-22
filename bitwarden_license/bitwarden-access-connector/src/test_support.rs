//! Helpers shared by the unit tests. Integration tests keep their own copy in `tests/common`.

use std::sync::LazyLock;

use bitwarden_access_token::{AccessToken, AccessTokenKind, make_access_token_secrets};
use bitwarden_api_api::models::CipherRequestModel;
use bitwarden_core::{
    OrganizationId,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};
use bitwarden_crypto::{
    BitwardenLegacyKeyBytes, Decryptable, EncString, KeyDecryptable, KeyEncryptable, KeyStore,
    SymmetricCryptoKey, SymmetricKeyAlgorithm,
};
use bitwarden_encoding::{B64, B64Url};
use bitwarden_pam_sealed::{
    RotationConfigSealedV1, Sealed, SealedPasswordPolicy, SealedTargetSystemKind,
    SealedTargetSystemMethod, TargetSystemSealedV1,
};
use bitwarden_vault::CipherView;
use uuid::Uuid;

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

/// An access token carrying `organization_id`; `tag` lands in the subject claim to tell tokens
/// apart. Only the claims segment is real.
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

/// A real token and its derived key, minted together so they agree.
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

/// The org key every cipher vector in `tests/fixtures/ciphers` is encrypted under (base64 of the
/// encoded `SymmetricCryptoKey`).
pub(crate) const ORG_KEY_B64: &str =
    "a4oGKmzuPXlJr6ANfFLy9DHw7lmaCo47mc01fROBKMUklVouVlwvgGsX1Sz9D9JHKbqOku/K25akClXWyp8a4g==";

/// The revision and creation date every cipher vector carries, with a millisecond part the write
/// must truncate.
pub(crate) const CIPHER_REVISION_DATE: &str = "2024-06-01T12:00:00.123Z";

/// Org cipher with its own item key, a URI, notes and one password-history entry.
pub(crate) const KEYED_LOGIN: &str = include_str!("../tests/fixtures/ciphers/keyed_login.json");
pub(crate) const KEYED_LOGIN_ID: uuid::Uuid = uuid::uuid!("8e1f3a2b-5c4d-4e6f-9a7b-0c1d2e3f4a5b");
/// [`KEYED_LOGIN`] plus an attachment with its own key.
pub(crate) const KEYED_LOGIN_WITH_ATTACHMENT_ID: uuid::Uuid =
    uuid::uuid!("9f2a4b3c-6d5e-4f70-8b8c-1d2e3f4a5b6c");
pub(crate) const KEYED_LOGIN_WITH_ATTACHMENT: &str =
    include_str!("../tests/fixtures/ciphers/keyed_login_with_attachment.json");
/// Older-style cipher: no item key, every field encrypted directly under the org key.
pub(crate) const KEYLESS_LOGIN: &str = include_str!("../tests/fixtures/ciphers/keyless_login.json");
pub(crate) const KEYLESS_LOGIN_ID: uuid::Uuid = uuid::uuid!("a03b5c4d-7e6f-4081-9c9d-2e3f4a5b6c7d");
/// Server-restricted cipher: carries `partialData`.
pub(crate) const RESTRICTED_LOGIN: &str =
    include_str!("../tests/fixtures/ciphers/restricted_login.json");

pub(crate) const RESTRICTED_LOGIN_ID: uuid::Uuid =
    uuid::uuid!("b14c6d5e-8f70-4192-8dae-3f4a5b6c7d8e");

/// The org key the cipher vectors are encrypted under.
pub(crate) fn fixture_org_key() -> SymmetricCryptoKey {
    SymmetricCryptoKey::try_from(B64::try_from(ORG_KEY_B64).expect("valid b64"))
        .expect("valid org key")
}

/// A vector's JSON, for tests to edit before serving it.
pub(crate) fn vector_json(vector: &str) -> serde_json::Value {
    serde_json::from_str(vector).expect("vector is JSON")
}

/// [`KEYED_LOGIN`] as the GET response JSON.
pub(crate) fn keyed_login_json() -> serde_json::Value {
    vector_json(KEYED_LOGIN)
}

/// The `attachments` array of [`KEYED_LOGIN_WITH_ATTACHMENT`], for grafting onto another vector.
pub(crate) fn attachments_json() -> serde_json::Value {
    vector_json(KEYED_LOGIN_WITH_ATTACHMENT)["attachments"].clone()
}

/// A key store holding the vectors' org key in the test org's slot.
pub(crate) fn org_store() -> KeyStore<KeySlotIds> {
    let store = KeyStore::default();
    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(test_org_slot(), fixture_org_key())
        .expect("set_symmetric_key");
    store
}

/// Decrypts the string at JSON pointer `pointer` in a cipher write `body` under the item key its
/// own `key` carries.
pub(crate) fn decrypt_body_field(
    store: &KeyStore<KeySlotIds>,
    body: &serde_json::Value,
    pointer: &str,
) -> String {
    // The body is the real request type, not just JSON that happens to decrypt.
    serde_json::from_value::<CipherRequestModel>(body.clone())
        .expect("body is a CipherRequestModel");
    let mut ctx = store.context_mut();
    let wrapped: EncString = body["key"]
        .as_str()
        .expect("body carries a key")
        .parse()
        .expect("key parses");
    let item_key = ctx
        .unwrap_symmetric_key(test_org_slot(), &wrapped)
        .expect("item key unwraps under the org key");
    let enc: EncString = body
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("no string at {pointer}"))
        .parse()
        .expect("field parses");
    enc.decrypt(&mut ctx, item_key).expect("field decrypts")
}

/// `(sealedData, wrappedKey)` as sent over the wire.
pub(crate) type SealedStrings = (String, String);

pub(crate) fn strong_policy() -> SealedPasswordPolicy {
    SealedPasswordPolicy {
        min_length: 20,
        max_length: 20,
        include_uppercase: true,
        include_lowercase: true,
        include_digits: true,
        include_symbols: true,
    }
}

pub(crate) fn sample_target(target_system_id: Uuid) -> TargetSystemSealedV1 {
    TargetSystemSealedV1 {
        target_system_id,
        method: SealedTargetSystemMethod::Automatic,
        kind: Some(SealedTargetSystemKind::CustomScript),
        password_policy: strong_policy(),
        supports_session_termination: Some(true),
    }
}

pub(crate) fn sample_config(target_system_id: Uuid, cipher_id: Uuid) -> RotationConfigSealedV1 {
    RotationConfigSealedV1 {
        target_system_id,
        cipher_id,
        account_identity: "svc-rotation@example.com".to_owned(),
        terminate_sessions: true,
    }
}

pub(crate) fn sealed_pair(
    store: &KeyStore<KeySlotIds>,
    target: TargetSystemSealedV1,
    config: RotationConfigSealedV1,
) -> (SealedStrings, SealedStrings) {
    let mut ctx = store.context_mut();
    let target_blob =
        bitwarden_pam_sealed::seal_target_system::<KeySlotIds>(target, &test_org_slot(), &mut ctx)
            .expect("seal target");
    let config_blob = bitwarden_pam_sealed::seal_rotation_config::<KeySlotIds>(
        config,
        &test_org_slot(),
        &mut ctx,
    )
    .expect("seal config");
    (strings(target_blob), strings(config_blob))
}

/// Wire form of a [`Sealed`]: `(sealedData, wrappedKey)`.
pub(crate) fn strings(sealed: Sealed) -> SealedStrings {
    (sealed.envelope.to_string(), sealed.wrapped_key.to_string())
}

/// Pins the recorded cipher vectors: the GET response shape the connector must keep accepting.
#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::CipherMiniResponseModel;
    use bitwarden_vault::Cipher;

    use super::*;

    fn strict_view(vector: &str) -> (Cipher, CipherView) {
        let model: CipherMiniResponseModel = serde_json::from_str(vector).expect("model");
        let cipher = Cipher::try_from(model).expect("cipher");
        let view: CipherView = org_store().decrypt(&cipher).expect("decrypt");
        (cipher, view)
    }

    fn assert_full_login(view: &CipherView) {
        assert_eq!(view.name, "Prod database");
        assert_eq!(view.notes.as_deref(), Some("rotated by PAM"));
        assert_eq!(view.organization_id, Some(test_org_id()));
        let login = view.login.as_ref().expect("login");
        assert_eq!(login.username.as_deref(), Some("svc-account"));
        assert_eq!(login.password.as_deref(), Some("old-password"));
        let uris = login.uris.as_ref().expect("uris");
        assert_eq!(uris[0].uri.as_deref(), Some("https://db.example.com"));
        let history = view.password_history.as_ref().expect("history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].password, "older-password");
        assert_eq!(
            view.revision_date,
            CIPHER_REVISION_DATE
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap()
        );
    }

    #[test]
    fn keyed_login_vector() {
        let (cipher, view) = strict_view(KEYED_LOGIN);
        assert!(cipher.key.is_some());
        assert_eq!(view.id.map(uuid::Uuid::from), Some(KEYED_LOGIN_ID));
        assert!(view.attachments.as_ref().is_none_or(Vec::is_empty));
        assert_full_login(&view);
    }

    #[test]
    fn keyed_login_with_attachment_vector() {
        let (cipher, view) = strict_view(KEYED_LOGIN_WITH_ATTACHMENT);
        assert!(cipher.key.is_some());
        assert_full_login(&view);
        let attachments = view.attachments.expect("attachments");
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].id.as_deref(), Some("att-1"));
        assert_eq!(attachments[0].file_name.as_deref(), Some("report.pdf"));
        assert!(attachments[0].key.is_some());
    }

    #[test]
    fn keyless_login_vector() {
        let (cipher, view) = strict_view(KEYLESS_LOGIN);
        assert!(cipher.key.is_none());
        assert_full_login(&view);
    }

    #[test]
    fn restricted_login_vector() {
        let (cipher, view) = strict_view(RESTRICTED_LOGIN);
        assert!(cipher.partial_data.is_some());
        assert!(cipher.key.is_some());
        assert!(view.partial);
        assert_eq!(view.name, "Prod database");
        let login = view.login.as_ref().expect("login");
        assert_eq!(
            login.uris.as_ref().expect("uris")[0].uri.as_deref(),
            Some("https://db.example.com")
        );
        assert!(login.password.is_none());
    }
}
