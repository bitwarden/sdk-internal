//! The vault cipher half of a rotation.
//!
//! [`decrypt_cipher_for_rotation`] vets and strictly decrypts the cipher the server returned, and
//! [`rotate_cipher_password`] builds the write that replaces its password. Both go through the
//! vault's typed models.

use bitwarden_api_api::models::CipherRequestModel;
use bitwarden_core::{OrganizationId, key_management::KeySlotIds};
use bitwarden_crypto::{EncString, KeyStore};
use bitwarden_vault::{Cipher, CipherType, CipherView, EncryptMode, StrictDecrypt};
use thiserror::Error;

/// Errors from the cipher half of a rotation. They never include cipher content.
#[derive(Debug, Error)]
pub enum RotationCipherError {
    /// The cipher belongs to a different organization than the connector's.
    #[error("cipher does not belong to the connector's organization")]
    CipherOrganizationMismatch,

    /// The cipher is not a login, or has no login data.
    #[error("cipher is not a login")]
    CipherNotLogin,

    /// The server returned a restricted cipher, which must never be rotated.
    #[error("cipher is restricted")]
    CipherRestricted,

    /// The cipher has no item key. Rotating it would make the vault generate a new one, and the
    /// rotation never changes the item key.
    #[error("cipher has no item key")]
    CipherWithoutItemKey,

    /// The re-encrypted cipher carries a `data` blob, which the server rejects.
    #[error("re-encrypted cipher carries a data blob")]
    CipherDataPresent,

    /// A generic cryptographic operation failed.
    #[error("cryptographic operation failed")]
    Crypto(#[from] bitwarden_crypto::CryptoError),

    /// JSON serialisation/deserialisation error.
    #[error("JSON error")]
    Json(#[from] serde_json::Error),
}

/// Decrypts the fetched cipher for a rotation. Before decrypting, rejects a cipher outside the
/// connector's organization, a non-login, a restricted one (re-encrypting would wipe the
/// withheld fields), or one without an item key (a rotation would make the vault generate one).
/// Decryption is strict: a field that fails to decrypt is an error, not silently dropped.
///
/// Returns the view together with the cipher's original wrapped item key, which the rotation
/// write must send back unchanged.
pub fn decrypt_cipher_for_rotation(
    key_store: &KeyStore<KeySlotIds>,
    organization_id: OrganizationId,
    cipher: Cipher,
) -> Result<(CipherView, EncString), RotationCipherError> {
    if cipher.organization_id != Some(organization_id) {
        return Err(RotationCipherError::CipherOrganizationMismatch);
    }
    if cipher.r#type != CipherType::Login {
        return Err(RotationCipherError::CipherNotLogin);
    }
    if cipher.partial_data.is_some() {
        return Err(RotationCipherError::CipherRestricted);
    }
    let original_key = cipher
        .key
        .clone()
        .ok_or(RotationCipherError::CipherWithoutItemKey)?;

    let view: CipherView = key_store.decrypt(&StrictDecrypt(cipher))?;
    if view.login.is_none() {
        return Err(RotationCipherError::CipherNotLogin);
    }
    Ok((view, original_key))
}

/// Builds the cipher write rotating `original`'s password to `new_password`: the old password
/// moves into the password history and the revision date is set; the rest carries over.
///
/// Uses field-level encryption (`EncryptMode::Legacy`), since the server rejects `data` on an
/// organization cipher.
///
/// The request's `key` is `original_key`, the item key as fetched, never the one the vault
/// emits. Encryption re-wraps the view's decrypted item key under the org key with a fresh IV,
/// so the emitted string differs but wraps the same key the new fields are encrypted under;
/// the original therefore unwraps to the right key, and the server requires it unchanged.
pub fn rotate_cipher_password(
    key_store: &KeyStore<KeySlotIds>,
    original: &CipherView,
    original_key: &EncString,
    new_password: &str,
) -> Result<CipherRequestModel, RotationCipherError> {
    let mut view = original.clone();
    view.login
        .as_mut()
        .ok_or(RotationCipherError::CipherNotLogin)?
        .password = Some(new_password.to_owned());
    view.update_password_history(original);

    let cipher = key_store.encrypt(EncryptMode::Legacy(view))?;
    let mut request = CipherRequestModel::try_from(cipher)?;
    request.key = Some(original_key.to_string());
    if request.data.is_some() {
        return Err(RotationCipherError::CipherDataPresent);
    }
    Ok(request)
}

/// Fixture builders for the tests below.
#[cfg(test)]
mod test_support {
    use bitwarden_crypto::{Decryptable, SymmetricCryptoKey};

    use super::*;

    pub(super) fn org_id() -> OrganizationId {
        "3f1a5c4e-7b2d-4f8a-9c6e-1d2b3a4c5d6e"
            .parse()
            .expect("valid uuid")
    }

    /// The org key every cipher vector in `tests/fixtures/ciphers` is encrypted under (base64 of
    /// the encoded `SymmetricCryptoKey`).
    const ORG_KEY_B64: &str =
        "a4oGKmzuPXlJr6ANfFLy9DHw7lmaCo47mc01fROBKMUklVouVlwvgGsX1Sz9D9JHKbqOku/K25akClXWyp8a4g==";

    /// Org cipher with its own item key, a URI, notes and one password-history entry.
    pub(super) const KEYED_LOGIN: &str =
        include_str!("../../tests/fixtures/ciphers/keyed_login.json");
    /// `KEYED_LOGIN` plus an attachment with its own key.
    pub(super) const KEYED_LOGIN_WITH_ATTACHMENT: &str =
        include_str!("../../tests/fixtures/ciphers/keyed_login_with_attachment.json");
    /// Older-style cipher: no item key, every field encrypted directly under the org key.
    pub(super) const KEYLESS_LOGIN: &str =
        include_str!("../../tests/fixtures/ciphers/keyless_login.json");
    /// Server-restricted cipher: carries `partialData`.
    pub(super) const RESTRICTED_LOGIN: &str =
        include_str!("../../tests/fixtures/ciphers/restricted_login.json");

    /// A vector's JSON, for tests to edit before decrypting it.
    pub(super) fn vector_json(vector: &str) -> serde_json::Value {
        serde_json::from_str(vector).expect("vector is JSON")
    }

    /// `KEYED_LOGIN` as the GET response JSON.
    pub(super) fn keyed_login_json() -> serde_json::Value {
        vector_json(KEYED_LOGIN)
    }

    /// The `attachments` array of `KEYED_LOGIN_WITH_ATTACHMENT`, for grafting onto another vector.
    pub(super) fn attachments_json() -> serde_json::Value {
        vector_json(KEYED_LOGIN_WITH_ATTACHMENT)["attachments"].clone()
    }

    /// A key store holding the vectors' org key in the test org's slot.
    pub(super) fn org_store() -> KeyStore<KeySlotIds> {
        let org_key: SymmetricCryptoKey = ORG_KEY_B64.parse().expect("valid org key");
        let store = KeyStore::default();
        #[allow(deprecated)]
        store
            .context_mut()
            .set_symmetric_key(
                bitwarden_core::key_management::SymmetricKeySlotId::Organization(org_id()),
                org_key,
            )
            .expect("set_symmetric_key");
        store
    }

    /// Decrypts the string at JSON pointer `pointer` in a cipher write `body` under the item key
    /// its own `key` carries.
    pub(super) fn decrypt_body_field(
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
            .unwrap_symmetric_key(
                bitwarden_core::key_management::SymmetricKeySlotId::Organization(org_id()),
                &wrapped,
            )
            .expect("item key unwraps under the org key");
        let enc: EncString = body
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("no string at {pointer}"))
            .parse()
            .expect("field parses");
        enc.decrypt(&mut ctx, item_key).expect("field decrypts")
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{KeyEncryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm};

    use super::{test_support::*, *};

    fn cipher_from(json: serde_json::Value) -> Cipher {
        let model: bitwarden_api_api::models::CipherMiniResponseModel =
            serde_json::from_value(json).expect("model");
        Cipher::try_from(model).expect("cipher")
    }

    #[test]
    fn decrypt_cipher_for_rotation_round_trips_and_returns_original_key() {
        let store = org_store();
        let json = keyed_login_json();
        let original_key = json["key"].as_str().expect("key").to_owned();

        let (view, key) =
            decrypt_cipher_for_rotation(&store, org_id(), cipher_from(json)).expect("decrypt");
        assert_eq!(key.to_string(), original_key);
        let login = view.login.as_ref().expect("login");
        assert_eq!(login.password.as_deref(), Some("old-password"));
        assert_eq!(login.username.as_deref(), Some("svc-account"));
        assert_eq!(view.name, "Prod database");
    }

    #[test]
    fn decrypt_cipher_for_rotation_rejects_cipher_without_item_key() {
        let store = org_store();
        let json = vector_json(KEYLESS_LOGIN);

        let result = decrypt_cipher_for_rotation(&store, org_id(), cipher_from(json));
        assert!(matches!(
            result,
            Err(RotationCipherError::CipherWithoutItemKey)
        ));
    }

    #[test]
    fn decrypt_cipher_for_rotation_rejects_other_organization() {
        let store = org_store();
        let mut json = keyed_login_json();
        json["organizationId"] = uuid::Uuid::new_v4().to_string().into();

        let result = decrypt_cipher_for_rotation(&store, org_id(), cipher_from(json));
        assert!(matches!(
            result,
            Err(RotationCipherError::CipherOrganizationMismatch)
        ));
    }

    #[test]
    fn decrypt_cipher_for_rotation_rejects_missing_organization() {
        let store = org_store();
        let mut json = keyed_login_json();
        json.as_object_mut().unwrap().remove("organizationId");

        let result = decrypt_cipher_for_rotation(&store, org_id(), cipher_from(json));
        assert!(matches!(
            result,
            Err(RotationCipherError::CipherOrganizationMismatch)
        ));
    }

    #[test]
    fn decrypt_cipher_for_rotation_rejects_non_login_type() {
        let store = org_store();
        let mut json = keyed_login_json();
        json["type"] = 2.into();

        let result = decrypt_cipher_for_rotation(&store, org_id(), cipher_from(json));
        assert!(matches!(result, Err(RotationCipherError::CipherNotLogin)));
    }

    #[test]
    fn decrypt_cipher_for_rotation_rejects_keyless_cipher_with_attachments() {
        let store = org_store();
        // The keyless vector with the attachments of the keyed one grafted on.
        let mut json = vector_json(KEYLESS_LOGIN);
        json["attachments"] = attachments_json();

        let result = decrypt_cipher_for_rotation(&store, org_id(), cipher_from(json));
        assert!(matches!(
            result,
            Err(RotationCipherError::CipherWithoutItemKey)
        ));
    }

    #[test]
    fn decrypt_cipher_for_rotation_accepts_attachments_with_item_key() {
        let store = org_store();
        let json = vector_json(KEYED_LOGIN_WITH_ATTACHMENT);

        let result = decrypt_cipher_for_rotation(&store, org_id(), cipher_from(json));
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn decrypt_cipher_for_rotation_rejects_restricted_cipher() {
        let store = org_store();
        let json = vector_json(RESTRICTED_LOGIN);

        let result = decrypt_cipher_for_rotation(&store, org_id(), cipher_from(json));
        assert!(matches!(result, Err(RotationCipherError::CipherRestricted)));
    }

    #[test]
    fn decrypt_cipher_for_rotation_rejects_login_without_login_data() {
        let store = org_store();
        let mut json = keyed_login_json();
        json.as_object_mut().unwrap().remove("login");

        let result = decrypt_cipher_for_rotation(&store, org_id(), cipher_from(json));
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_cipher_for_rotation_rejects_undecryptable_field() {
        let store = org_store();
        let other_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let foreign = "x"
            .encrypt_with_key(&other_key)
            .expect("encrypt")
            .to_string();

        for field in ["/login/password", "/login/username", "/notes", "/name"] {
            let mut json = keyed_login_json();
            *json.pointer_mut(field).expect("field present") = foreign.clone().into();

            let result = decrypt_cipher_for_rotation(&store, org_id(), cipher_from(json));
            assert!(result.is_err(), "{field}: must not decrypt");
        }
    }

    fn decrypted_json(store: &KeyStore<KeySlotIds>, request: &CipherRequestModel) -> Vec<String> {
        let body = serde_json::to_value(request).expect("serialize");
        [
            "/login/password",
            "/login/username",
            "/login/uris/0/uri",
            "/name",
            "/notes",
            "/passwordHistory/0/password",
        ]
        .iter()
        .map(|p| decrypt_body_field(store, &body, p))
        .collect()
    }

    #[test]
    fn rotate_cipher_password_rewrites_password_and_history() {
        let store = org_store();
        {
            let label = "item key";
            let json = keyed_login_json();
            let original_key = json["key"].as_str().expect("key").to_owned();
            let (view, key) =
                decrypt_cipher_for_rotation(&store, org_id(), cipher_from(json)).expect("decrypt");

            let request = rotate_cipher_password(&store, &view, &key, "new-pw").expect("rotate");

            assert!(request.data.is_none(), "{label}");
            assert_eq!(
                request.key.as_deref(),
                Some(original_key.as_str()),
                "{label}: write carries the original item key"
            );
            assert_eq!(
                request.organization_id,
                Some(org_id().to_string()),
                "{label}"
            );
            assert_eq!(
                request.r#type,
                Some(bitwarden_api_api::models::CipherType::Login),
                "{label}"
            );
            assert_eq!(
                request.last_known_revision_date.as_deref(),
                Some("2024-06-01T12:00:00Z"),
                "{label}"
            );
            let body = serde_json::to_value(&request).expect("serialize");
            assert!(body["login"]["passwordRevisionDate"].is_string(), "{label}");

            assert_eq!(
                decrypted_json(&store, &request),
                [
                    "new-pw",
                    "svc-account",
                    "https://db.example.com",
                    "Prod database",
                    "rotated by PAM",
                    "old-password",
                ],
                "{label}"
            );
            // The older entry follows the new one.
            assert_eq!(
                decrypt_body_field(&store, &body, "/passwordHistory/1/password"),
                "older-password",
                "{label}"
            );
        }
    }

    #[test]
    fn rotate_cipher_password_without_old_password_adds_no_history_entry() {
        let store = org_store();
        {
            let label = "item key";
            let mut json = keyed_login_json();
            json["login"]["password"] = serde_json::Value::Null;
            let (view, key) =
                decrypt_cipher_for_rotation(&store, org_id(), cipher_from(json)).expect("decrypt");

            let request = rotate_cipher_password(&store, &view, &key, "first-pw").expect("rotate");
            let body = serde_json::to_value(&request).expect("serialize");

            assert_eq!(
                decrypt_body_field(&store, &body, "/login/password"),
                "first-pw",
                "{label}"
            );
            assert!(body["login"]["passwordRevisionDate"].is_string(), "{label}");
            // Only the pre-existing entry remains.
            assert_eq!(
                body["passwordHistory"].as_array().map(Vec::len),
                Some(1),
                "{label}"
            );
            assert_eq!(
                decrypt_body_field(&store, &body, "/passwordHistory/0/password"),
                "older-password",
                "{label}"
            );
        }
    }
}
