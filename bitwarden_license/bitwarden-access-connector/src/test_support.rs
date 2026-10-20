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
    PrimitiveEncryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm,
};
use bitwarden_encoding::{B64, B64Url};
use bitwarden_vault::{
    CipherId, CipherRepromptType, CipherType, CipherView, EncryptMode, LoginUriView, LoginView,
    PasswordHistoryView,
};

use crate::api::{
    AccessConnectorClient, AccessConnectorClientExt as _, REQUEST_TIMEOUT, build_sdk_client,
};

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

/// A key store holding a fresh org key in the test org's slot.
pub(crate) fn org_store() -> KeyStore<KeySlotIds> {
    let store = KeyStore::default();
    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(
            test_org_slot(),
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
        )
        .expect("set_symmetric_key");
    store
}

/// The revision date the cipher fixtures carry, with a millisecond part the write must truncate.
pub(crate) const CIPHER_REVISION_DATE: &str = "2024-06-01T12:00:00.123Z";

/// A login cipher view in the test org with a username, URI, notes, a hidden custom field and one
/// history entry, so a rotation has something to preserve.
pub(crate) fn login_view(cipher_id: uuid::Uuid, password: Option<&str>) -> CipherView {
    let revision_date = CIPHER_REVISION_DATE.parse().expect("valid date");
    CipherView {
        partial: false,
        id: Some(CipherId::new(cipher_id)),
        organization_id: Some(test_org_id()),
        folder_id: None,
        collection_ids: vec![],
        key: None,
        name: "Prod database".to_owned(),
        notes: Some("rotated by PAM".to_owned()),
        r#type: CipherType::Login,
        login: Some(LoginView {
            username: Some("svc-account".to_owned()),
            password: password.map(str::to_owned),
            password_revision_date: None,
            uris: Some(vec![LoginUriView {
                uri: Some("https://db.example.com".to_owned()),
                r#match: None,
                uri_checksum: None,
            }]),
            totp: None,
            autofill_on_page_load: None,
            fido2_credentials: None,
        }),
        identity: None,
        card: None,
        secure_note: None,
        ssh_key: None,
        bank_account: None,
        drivers_license: None,
        passport: None,
        favorite: false,
        reprompt: CipherRepromptType::None,
        organization_use_totp: true,
        edit: true,
        permissions: None,
        view_password: true,
        local_data: None,
        attachments: None,
        attachment_decryption_failures: None,
        fields: None,
        password_history: Some(vec![PasswordHistoryView {
            password: "older-password".to_owned(),
            last_used_date: "2024-01-01T00:00:00Z".parse().expect("valid date"),
        }]),
        creation_date: revision_date,
        deleted_date: None,
        revision_date,
        archived_date: None,
    }
}

/// The wire `CipherMiniResponseModel` for `view`, encrypted by the vault under the org key in
/// `store`. The vault always gives the cipher its own wrapped item key.
pub(crate) fn cipher_json(store: &KeyStore<KeySlotIds>, view: &CipherView) -> serde_json::Value {
    let cipher = store
        .encrypt(EncryptMode::Legacy(view.clone()))
        .expect("encrypt cipher");
    let request = CipherRequestModel::try_from(cipher).expect("request model");

    // A request and a mini response share the cipher's field shapes.
    let mut json = serde_json::to_value(request).expect("serialize");
    let obj = json.as_object_mut().expect("object");
    obj.remove("lastKnownRevisionDate");
    obj.insert("id".to_owned(), view.id.map(|id| id.to_string()).into());
    obj.insert("creationDate".to_owned(), CIPHER_REVISION_DATE.into());
    obj.insert("revisionDate".to_owned(), CIPHER_REVISION_DATE.into());
    json
}

/// Like [`cipher_json`], but with every field encrypted directly under the org key and no item key.
pub(crate) fn keyless_cipher_json(
    store: &KeyStore<KeySlotIds>,
    view: &CipherView,
) -> serde_json::Value {
    let mut ctx = store.context();
    let mut enc = |s: &str| {
        s.encrypt(&mut ctx, test_org_slot())
            .expect("encrypt")
            .to_string()
    };
    let login = view.login.as_ref().expect("login view");
    serde_json::json!({
        "id": view.id.map(|id| id.to_string()),
        "organizationId": test_org_id().to_string(),
        "type": 1,
        "name": enc(&view.name),
        "notes": view.notes.as_deref().map(&mut enc),
        "login": {
            "username": login.username.as_deref().map(&mut enc),
            "password": login.password.as_deref().map(&mut enc),
            "uris": login.uris.iter().flatten().map(|u| serde_json::json!({
                "uri": u.uri.as_deref().map(&mut enc),
            })).collect::<Vec<_>>(),
        },
        "passwordHistory": view.password_history.iter().flatten().map(|h| serde_json::json!({
            "password": enc(&h.password),
            "lastUsedDate": h.last_used_date.to_rfc3339(),
        })).collect::<Vec<_>>(),
        "creationDate": CIPHER_REVISION_DATE,
        "revisionDate": CIPHER_REVISION_DATE,
    })
}

/// Decrypts the string at JSON pointer `pointer` in a cipher write `body`, under the item key
/// that the body's own `key` carries, as the server's clients would.
pub(crate) fn decrypt_body_field(
    store: &KeyStore<KeySlotIds>,
    body: &serde_json::Value,
    pointer: &str,
) -> String {
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

/// An [`AccessConnectorClient`] whose key store is `store`. Its API configurations point at an
/// unreachable address, so only the crypto methods are usable.
pub(crate) fn client_with_store(store: &KeyStore<KeySlotIds>) -> AccessConnectorClient {
    let (tx, _rx) = tokio::sync::watch::channel(std::time::Instant::now());
    let (client, _handler) = build_sdk_client(
        "http://127.0.0.1:1".to_owned(),
        "http://127.0.0.1:1".to_owned(),
        REQUEST_TIMEOUT,
        tx,
    );
    AccessConnectorClient {
        key_store: store.clone(),
        ..client.access_connector()
    }
}
