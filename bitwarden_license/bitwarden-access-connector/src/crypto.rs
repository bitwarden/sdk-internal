//! Cryptographic helpers used by the access connector.
//!
//! The org slot is keyed by the [`OrganizationId`] from the access token's `organization` claim.
//! Cipher handling, on `AccessConnectorClient`, goes through the vault's typed models: decrypt,
//! replace the login password, re-encrypt.

use bitwarden_access_token::{AccessToken, AccessTokenError};
use bitwarden_api_api::models::CipherRequestModel;
use bitwarden_core::{
    OrganizationId,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};
use bitwarden_crypto::KeyStore;
use bitwarden_vault::{Cipher, CipherType, CipherView, EncryptMode, StrictDecrypt};
use thiserror::Error;

use crate::api::AccessConnectorClient;

/// Errors produced by the cryptographic helpers in this module.
#[derive(Debug, Error)]
pub(crate) enum CryptoModuleError {
    /// An encrypted payload or wrapped cipher key could not be decoded or decrypted.
    #[error("org-key payload is invalid")]
    InvalidPayload,

    /// The decrypted payload does not contain a valid org key.
    #[error("org-key payload does not contain a valid encryption key")]
    InvalidOrgKey,

    /// The cipher belongs to a different organization than the connector's.
    #[error("cipher does not belong to the connector's organization")]
    CipherOrganizationMismatch,

    /// The cipher is not a login, or has no login data.
    #[error("cipher is not a login")]
    CipherNotLogin,

    /// The server returned a restricted cipher, which must never be rotated.
    #[error("cipher is restricted")]
    CipherRestricted,

    /// The cipher has attachments but no per-item key. Vault encryption would generate an item key
    /// and re-wrap the attachment keys under it, but the rotation write stores only the cipher data
    /// and key, so the stored attachment keys would no longer unwrap.
    #[error("cipher has attachments but no item key")]
    CipherAttachmentsWithoutItemKey,

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

/// Decrypt the identity server's `encrypted_payload` with `token`'s derived key and install the org
/// key into `store`. Errors carry no payload content.
pub(crate) fn unwrap_org_key(
    store: &KeyStore<KeySlotIds>,
    organization_id: OrganizationId,
    token: &AccessToken,
    encrypted_payload: &str,
) -> Result<(), CryptoModuleError> {
    let mut ctx = store.context_mut();

    token
        .open_payload(
            &mut ctx,
            encrypted_payload,
            SymmetricKeySlotId::Organization(organization_id),
        )
        .map_err(|e| match e {
            AccessTokenError::InvalidPayload => CryptoModuleError::InvalidPayload,
            AccessTokenError::InvalidOrgKey => CryptoModuleError::InvalidOrgKey,
            AccessTokenError::Crypto(c) => CryptoModuleError::Crypto(c),
        })
}

impl AccessConnectorClient {
    /// Decrypts the fetched cipher for a rotation. Rejects, before any decryption, a cipher outside
    /// the connector's organization, one that is not a login, a restricted one, or one with
    /// attachments but no item key: re-encrypting a restricted cipher would wipe the fields the
    /// server withheld, and the attachment keys of a cipher without an item key would be
    /// orphaned by the item key the write generates. Decryption is strict, so a field that
    /// fails to decrypt is an error rather than silently dropped from the later re-encrypt.
    pub(crate) fn decrypt_cipher_for_rotation(
        &self,
        organization_id: OrganizationId,
        cipher: Cipher,
    ) -> Result<CipherView, CryptoModuleError> {
        if cipher.organization_id != Some(organization_id) {
            return Err(CryptoModuleError::CipherOrganizationMismatch);
        }
        if cipher.r#type != CipherType::Login {
            return Err(CryptoModuleError::CipherNotLogin);
        }
        if cipher.partial_data.is_some() {
            return Err(CryptoModuleError::CipherRestricted);
        }
        if cipher.key.is_none() && cipher.attachments.as_ref().is_some_and(|a| !a.is_empty()) {
            return Err(CryptoModuleError::CipherAttachmentsWithoutItemKey);
        }

        let view: CipherView = self.key_store.decrypt(&StrictDecrypt(cipher))?;
        if view.login.is_none() {
            return Err(CryptoModuleError::CipherNotLogin);
        }
        Ok(view)
    }

    /// Builds the cipher write for rotating `original`'s password to `new_password`: the old
    /// password moves into the password history and the password revision date is set.
    /// Everything else is carried over from `original`.
    ///
    /// Uses the legacy field-level encryption, since the server rejects `data` on an organization
    /// cipher. The vault always emits a wrapped item key, re-wrapping an existing one or generating
    /// one for a cipher that had none.
    pub(crate) fn rotate_cipher_password(
        &self,
        original: &CipherView,
        new_password: &str,
    ) -> Result<CipherRequestModel, CryptoModuleError> {
        let mut view = original.clone();
        view.login
            .as_mut()
            .ok_or(CryptoModuleError::CipherNotLogin)?
            .password = Some(new_password.to_owned());
        view.update_password_history(original);

        let cipher = self.key_store.encrypt(EncryptMode::Legacy(view))?;
        let request = CipherRequestModel::try_from(cipher)?;
        if request.data.is_some() {
            return Err(CryptoModuleError::CipherDataPresent);
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_access_token::{AccessTokenKind, make_access_token_secrets};
    use bitwarden_crypto::{
        KeyDecryptable, KeyEncryptable, PrimitiveEncryptable, SymmetricCryptoKey,
        SymmetricKeyAlgorithm,
    };
    use uuid::uuid;

    use super::*;
    use crate::test_support::{
        cipher_json, client_with_store as client_for, decrypt_body_field, keyless_cipher_json,
        login_view, org_store, test_org_id as org_id,
    };

    fn org_slot() -> SymmetricKeySlotId {
        SymmetricKeySlotId::Organization(org_id())
    }

    fn make_store_with_org_key() -> (KeyStore<KeySlotIds>, SymmetricCryptoKey) {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);

        #[allow(deprecated)]
        store
            .context_mut()
            .set_symmetric_key(org_slot(), org_key.clone())
            .expect("set_symmetric_key");

        (store, org_key)
    }

    /// Mints a token the way `bitwarden-pam` does, keyed to the organization key in
    /// `issuer_store`, plus the `encrypted_payload` that goes with it.
    fn mint_token_and_payload(issuer_store: &KeyStore<KeySlotIds>) -> (AccessToken, String) {
        let secrets = {
            let mut ctx = issuer_store.context_mut();
            make_access_token_secrets(&mut ctx, org_slot(), AccessTokenKind::AccessConnector)
                .expect("mint secrets")
        };
        let encrypted_payload = secrets.encrypted_payload.to_string();
        let token_str = secrets.into_token(uuid!("22222222-2222-2222-2222-222222222222"), "secret");
        let token = AccessToken::parse(&token_str, AccessTokenKind::AccessConnector)
            .expect("the token parses");
        (token, encrypted_payload)
    }

    #[test]
    fn unwrap_org_key_round_trip() {
        let (issuer_store, org_key) = make_store_with_org_key();
        let (token, encrypted_payload) = mint_token_and_payload(&issuer_store);

        let store: KeyStore<KeySlotIds> = KeyStore::default();
        assert!(!store.context().has_symmetric_key(org_slot()));

        unwrap_org_key(&store, org_id(), &token, &encrypted_payload).expect("unwrap_org_key");

        // Probe that the org key is installed.
        let probe = "probe value";
        let encrypted_probe = {
            let mut ctx = store.context();
            probe.encrypt(&mut ctx, org_slot()).expect("encrypt probe")
        };

        let decrypted: String = encrypted_probe
            .decrypt_with_key(&org_key)
            .expect("decrypt probe");
        assert_eq!(decrypted, probe);
    }

    #[test]
    fn unwrap_org_key_bad_payload_returns_error() {
        let (issuer_store, _org_key) = make_store_with_org_key();
        let (token, _payload) = mint_token_and_payload(&issuer_store);
        let store: KeyStore<KeySlotIds> = KeyStore::default();

        let result = unwrap_org_key(&store, org_id(), &token, "not-an-enc-string");
        assert!(
            matches!(result, Err(CryptoModuleError::InvalidPayload)),
            "expected InvalidPayload, got {result:?}",
        );
    }

    fn cipher_from(json: serde_json::Value) -> Cipher {
        let model: bitwarden_api_api::models::CipherMiniResponseModel =
            serde_json::from_value(json).expect("model");
        Cipher::try_from(model).expect("cipher")
    }

    fn fixture_ciphers(
        store: &KeyStore<KeySlotIds>,
        password: Option<&str>,
    ) -> [(&'static str, serde_json::Value); 2] {
        let view = login_view(uuid::Uuid::new_v4(), password);
        [
            ("item key", cipher_json(store, &view)),
            ("no item key", keyless_cipher_json(store, &view)),
        ]
    }

    #[test]
    fn decrypt_cipher_for_rotation_round_trips_both_key_layouts() {
        let store = org_store();
        for (label, json) in fixture_ciphers(&store, Some("old-pw")) {
            let has_key = json.get("key").is_some_and(|k| !k.is_null());
            assert_eq!(has_key, label == "item key");

            let view = client_for(&store)
                .decrypt_cipher_for_rotation(org_id(), cipher_from(json))
                .unwrap_or_else(|e| panic!("{label}: {e}"));
            let login = view.login.as_ref().expect("login");
            assert_eq!(login.password.as_deref(), Some("old-pw"), "{label}");
            assert_eq!(login.username.as_deref(), Some("svc-account"), "{label}");
            assert_eq!(view.name, "Prod database", "{label}");
        }
    }

    #[test]
    fn decrypt_cipher_for_rotation_rejects_other_organization() {
        let store = org_store();
        let mut json = cipher_json(&store, &login_view(uuid::Uuid::new_v4(), Some("pw")));
        json["organizationId"] = uuid::Uuid::new_v4().to_string().into();

        let result = client_for(&store).decrypt_cipher_for_rotation(org_id(), cipher_from(json));
        assert!(matches!(
            result,
            Err(CryptoModuleError::CipherOrganizationMismatch)
        ));
    }

    #[test]
    fn decrypt_cipher_for_rotation_rejects_missing_organization() {
        let store = org_store();
        let mut json = cipher_json(&store, &login_view(uuid::Uuid::new_v4(), Some("pw")));
        json.as_object_mut().unwrap().remove("organizationId");

        let result = client_for(&store).decrypt_cipher_for_rotation(org_id(), cipher_from(json));
        assert!(matches!(
            result,
            Err(CryptoModuleError::CipherOrganizationMismatch)
        ));
    }

    #[test]
    fn decrypt_cipher_for_rotation_rejects_non_login_type() {
        let store = org_store();
        let mut json = cipher_json(&store, &login_view(uuid::Uuid::new_v4(), Some("pw")));
        json["type"] = 2.into();

        let result = client_for(&store).decrypt_cipher_for_rotation(org_id(), cipher_from(json));
        assert!(matches!(result, Err(CryptoModuleError::CipherNotLogin)));
    }

    fn with_attachment(json: &mut serde_json::Value) {
        json["attachments"] = serde_json::json!([{"id": "att-1", "size": "10"}]);
    }

    #[test]
    fn decrypt_cipher_for_rotation_rejects_attachments_without_item_key() {
        let store = org_store();
        let view = login_view(uuid::Uuid::new_v4(), Some("pw"));
        let mut json = keyless_cipher_json(&store, &view);
        with_attachment(&mut json);

        let result = client_for(&store).decrypt_cipher_for_rotation(org_id(), cipher_from(json));
        assert!(matches!(
            result,
            Err(CryptoModuleError::CipherAttachmentsWithoutItemKey)
        ));
    }

    #[test]
    fn decrypt_cipher_for_rotation_accepts_attachments_with_item_key() {
        let store = org_store();
        let mut json = cipher_json(&store, &login_view(uuid::Uuid::new_v4(), Some("pw")));
        with_attachment(&mut json);

        let result = client_for(&store).decrypt_cipher_for_rotation(org_id(), cipher_from(json));
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn decrypt_cipher_for_rotation_rejects_restricted_cipher() {
        let store = org_store();
        let mut json = cipher_json(&store, &login_view(uuid::Uuid::new_v4(), Some("pw")));
        json["partialData"] = "{}".into();

        let result = client_for(&store).decrypt_cipher_for_rotation(org_id(), cipher_from(json));
        assert!(matches!(result, Err(CryptoModuleError::CipherRestricted)));
    }

    #[test]
    fn decrypt_cipher_for_rotation_rejects_login_without_login_data() {
        let store = org_store();
        let mut json = cipher_json(&store, &login_view(uuid::Uuid::new_v4(), Some("pw")));
        json.as_object_mut().unwrap().remove("login");

        let result = client_for(&store).decrypt_cipher_for_rotation(org_id(), cipher_from(json));
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
            for (label, mut json) in fixture_ciphers(&store, Some("pw")) {
                *json.pointer_mut(field).expect("field present") = foreign.clone().into();

                let result =
                    client_for(&store).decrypt_cipher_for_rotation(org_id(), cipher_from(json));
                assert!(result.is_err(), "{label} {field}: must not decrypt");
            }
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
        for (label, json) in fixture_ciphers(&store, Some("old-pw")) {
            let view = client_for(&store)
                .decrypt_cipher_for_rotation(org_id(), cipher_from(json))
                .expect("decrypt");

            let request = client_for(&store)
                .rotate_cipher_password(&view, "new-pw")
                .expect("rotate");

            assert!(request.data.is_none(), "{label}");
            assert!(request.key.is_some(), "{label}: write carries an item key");
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
                    "old-pw",
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
        for (label, json) in fixture_ciphers(&store, None) {
            let view = client_for(&store)
                .decrypt_cipher_for_rotation(org_id(), cipher_from(json))
                .expect("decrypt");

            let request = client_for(&store)
                .rotate_cipher_password(&view, "first-pw")
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
