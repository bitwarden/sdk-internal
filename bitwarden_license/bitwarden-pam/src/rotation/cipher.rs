//! The vault cipher half of a rotation.
//!
//! [`rotate_cipher_password`] vets the cipher the server returned and builds the write that
//! replaces its password. The vault owns the strict decryption, the password history and the
//! encryption ([`Cipher::change_login_password`]); this module adds the PAM vetting and the
//! original-item-key rule. It goes through the vault's typed models.

use bitwarden_api_api::models::CipherRequestModel;
use bitwarden_core::{OrganizationId, key_management::KeySlotIds};
use bitwarden_crypto::KeyStore;
use bitwarden_vault::{ChangeLoginPasswordError, Cipher, CipherType};
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

    /// Strict decryption or re-encryption failed.
    #[error("cryptographic operation failed")]
    Crypto(#[from] bitwarden_crypto::CryptoError),

    /// JSON serialisation/deserialisation error.
    #[error("JSON error")]
    Json(#[from] serde_json::Error),
}

impl From<ChangeLoginPasswordError> for RotationCipherError {
    fn from(err: ChangeLoginPasswordError) -> Self {
        match err {
            ChangeLoginPasswordError::PartialCipher => Self::CipherRestricted,
            ChangeLoginPasswordError::NotLogin => Self::CipherNotLogin,
            ChangeLoginPasswordError::Crypto(e) => Self::Crypto(e),
        }
    }
}

/// Builds the cipher write rotating `cipher`'s password to `new_password`. Before touching it,
/// rejects a cipher outside the connector's organization, a non-login, a restricted one
/// (re-encrypting would wipe the withheld fields), or one without an item key (a rotation would
/// make the vault generate one). The vault then decrypts strictly (a field that fails to decrypt
/// is an error, not silently dropped), moves the old password into the password history and
/// re-encrypts; the rest carries over.
///
/// Uses field-level encryption, since the server rejects `data` on an organization cipher.
///
/// The request's `key` is the item key as fetched, never the one the vault emits. Encryption
/// re-wraps the decrypted item key under the org key with a fresh IV, so the emitted string
/// differs but wraps the same key the new fields are encrypted under; the original therefore
/// unwraps to the right key, and the server requires it unchanged.
pub fn rotate_cipher_password(
    key_store: &KeyStore<KeySlotIds>,
    organization_id: OrganizationId,
    cipher: Cipher,
    new_password: &str,
) -> Result<CipherRequestModel, RotationCipherError> {
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

    let rotated = cipher.change_login_password(key_store, new_password)?;
    let mut request = CipherRequestModel::try_from(rotated)?;
    request.key = Some(original_key.to_string());
    if request.data.is_some() {
        return Err(RotationCipherError::CipherDataPresent);
    }
    Ok(request)
}

/// Fixture builders for the tests below.
#[cfg(test)]
mod test_support {
    use bitwarden_crypto::{Decryptable, EncString, SymmetricCryptoKey};

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

    const NEW_PW: &str = "new-pw";

    fn rotate(json: serde_json::Value) -> Result<CipherRequestModel, RotationCipherError> {
        rotate_cipher_password(&org_store(), org_id(), cipher_from(json), NEW_PW)
    }

    #[test]
    fn rotate_cipher_password_rejects_cipher_without_item_key() {
        let result = rotate(vector_json(KEYLESS_LOGIN));
        assert!(matches!(
            result,
            Err(RotationCipherError::CipherWithoutItemKey)
        ));
    }

    #[test]
    fn rotate_cipher_password_rejects_other_organization() {
        let mut json = keyed_login_json();
        json["organizationId"] = uuid::Uuid::new_v4().to_string().into();

        assert!(matches!(
            rotate(json),
            Err(RotationCipherError::CipherOrganizationMismatch)
        ));
    }

    #[test]
    fn rotate_cipher_password_rejects_missing_organization() {
        let mut json = keyed_login_json();
        json.as_object_mut().unwrap().remove("organizationId");

        assert!(matches!(
            rotate(json),
            Err(RotationCipherError::CipherOrganizationMismatch)
        ));
    }

    #[test]
    fn rotate_cipher_password_rejects_non_login_type() {
        let mut json = keyed_login_json();
        json["type"] = 2.into();

        assert!(matches!(
            rotate(json),
            Err(RotationCipherError::CipherNotLogin)
        ));
    }

    #[test]
    fn rotate_cipher_password_rejects_keyless_cipher_with_attachments() {
        // The keyless vector with the attachments of the keyed one grafted on.
        let mut json = vector_json(KEYLESS_LOGIN);
        json["attachments"] = attachments_json();

        assert!(matches!(
            rotate(json),
            Err(RotationCipherError::CipherWithoutItemKey)
        ));
    }

    #[test]
    fn rotate_cipher_password_accepts_attachments_with_item_key() {
        let result = rotate(vector_json(KEYED_LOGIN_WITH_ATTACHMENT));
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn rotate_cipher_password_rejects_restricted_cipher() {
        assert!(matches!(
            rotate(vector_json(RESTRICTED_LOGIN)),
            Err(RotationCipherError::CipherRestricted)
        ));
    }

    #[test]
    fn rotate_cipher_password_rejects_login_without_login_data() {
        let mut json = keyed_login_json();
        json.as_object_mut().unwrap().remove("login");

        assert!(rotate(json).is_err());
    }

    #[test]
    fn rotate_cipher_password_rejects_undecryptable_field() {
        let other_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let foreign = "x"
            .encrypt_with_key(&other_key)
            .expect("encrypt")
            .to_string();

        for field in ["/login/password", "/login/username", "/notes", "/name"] {
            let mut json = keyed_login_json();
            *json.pointer_mut(field).expect("field present") = foreign.clone().into();

            assert!(rotate(json).is_err(), "{field}: must not decrypt");
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
            let request = rotate_cipher_password(&store, org_id(), cipher_from(json), "new-pw")
                .expect("rotate");

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
            let request = rotate_cipher_password(&store, org_id(), cipher_from(json), "first-pw")
                .expect("rotate");
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
