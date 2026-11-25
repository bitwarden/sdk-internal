//! Reads a seeded cipher back through the Seeder and decrypts it with the organization key.

use bitwarden_core::{
    OrganizationId,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};
use bitwarden_crypto::{Decryptable, EncString, KeyStore, SymmetricCryptoKey};
use bitwarden_test::play::Play;
use uuid::Uuid;

use super::scenes::{OrganizationCipherArgs, OrganizationCipherQuery};

/// A login cipher's decrypted secrets and the stored fields that rotation must preserve.
#[derive(Debug, Clone)]
pub struct DecryptedLogin {
    pub password: String,
    /// Newest first, as stored.
    pub password_history: Vec<String>,
    /// The stored item key, unchanged.
    pub key: Option<String>,
    pub revision_date: String,
    /// The login's plaintext `PasswordRevisionDate`, when set.
    pub password_revision_date: Option<String>,
}

/// Fetches the cipher and decrypts its login password and history.
///
/// `Cipher.Data` is the server's `CipherLoginData` JSON, which uses PascalCase names, so names
/// are matched ignoring case. Fields are encrypted under the item key when the cipher has one,
/// else under the organization key.
pub async fn read_login(
    play: &Play,
    organization_id: Uuid,
    org_key: &SymmetricCryptoKey,
    cipher_id: Uuid,
) -> DecryptedLogin {
    let row = play
        .query::<OrganizationCipherQuery>(&OrganizationCipherArgs { cipher_id })
        .await
        .expect("OrganizationCipherQuery")
        .row;
    let data: serde_json::Value = serde_json::from_str(&row.data).expect("Cipher.Data is JSON");

    let org_slot = SymmetricKeySlotId::Organization(OrganizationId::new(organization_id));
    let store = KeyStore::<KeySlotIds>::default();
    let mut ctx = store.context_mut();
    #[allow(deprecated)]
    ctx.set_symmetric_key(org_slot, org_key.clone())
        .expect("set_symmetric_key");

    let field_key = match &row.key {
        Some(key) => {
            let wrapped: EncString = key.parse().expect("item key is an EncString");
            ctx.unwrap_symmetric_key(org_slot, &wrapped)
                .expect("item key unwraps under the org key")
        }
        None => org_slot,
    };

    let mut decrypt = |value: &serde_json::Value| -> String {
        let enc: EncString = value
            .as_str()
            .expect("encrypted field is a string")
            .parse()
            .expect("field is an EncString");
        enc.decrypt(&mut ctx, field_key).expect("field decrypts")
    };

    let password = decrypt(get(&data, "password").expect("login has a password"));
    let password_history = get(&data, "passwordHistory")
        .and_then(serde_json::Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .map(|entry| decrypt(get(entry, "password").expect("history entry password")))
                .collect()
        })
        .unwrap_or_default();
    let password_revision_date = get(&data, "passwordRevisionDate")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);

    DecryptedLogin {
        password,
        password_history,
        key: row.key,
        revision_date: row.revision_date,
        password_revision_date,
    }
}

/// The object member whose name equals `name` ignoring ASCII case.
fn get<'a>(value: &'a serde_json::Value, name: &str) -> Option<&'a serde_json::Value> {
    value
        .as_object()?
        .iter()
        .find(|(k, v)| k.eq_ignore_ascii_case(name) && !v.is_null())
        .map(|(_, v)| v)
}
