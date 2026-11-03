use bitwarden_core::key_management::KeySlotIds;
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use super::{
    cipher::{Cipher, CipherType, CipherView, EncryptMode, StrictDecrypt},
    cipher_client::should_use_blob_encryption,
};

/// Error returned by [`Cipher::change_login_password`].
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum ChangeLoginPasswordError {
    /// The cipher is partial, so re-encrypting it would drop its password history.
    #[error("Cannot change the password of a partial cipher")]
    PartialCipher,
    /// The cipher is not a login.
    #[error("Cannot change the login password of a cipher that is not a login")]
    NotLogin,
    /// Strict decryption or re-encryption failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl Cipher {
    /// Decrypts this cipher strictly, sets a new login password, records the old one in the
    /// password history, and re-encrypts it.
    pub fn change_login_password(
        self,
        key_store: &KeyStore<KeySlotIds>,
        new_password: &str,
    ) -> Result<Cipher, ChangeLoginPasswordError> {
        // A partial original has no password history to chain; see `edit_cipher`.
        if self.partial_data.is_some() {
            return Err(ChangeLoginPasswordError::PartialCipher);
        }
        if self.r#type != CipherType::Login {
            return Err(ChangeLoginPasswordError::NotLogin);
        }

        // Strict: an undecryptable field is an error, as re-encrypting would wipe it.
        let mut view: CipherView = key_store.decrypt(&StrictDecrypt(self))?;
        if view.login.is_none() {
            return Err(ChangeLoginPasswordError::NotLogin);
        }

        let original = view.clone();
        if let Some(login) = view.login.as_mut() {
            login.password = Some(new_password.to_owned());
        }
        view.update_password_history(&original);

        // The security state picks the format, as in the edit flows. Organization ciphers stay
        // field-level until the helper supports them (PM-32430), then switch here automatically.
        let use_blob = should_use_blob_encryption(&key_store.context(), view.organization_id);
        let mode = if use_blob {
            EncryptMode::Blob(view)
        } else {
            EncryptMode::Legacy(view)
        };
        Ok(key_store.encrypt(mode)?)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::{
        BLOB_SECURITY_VERSION, SymmetricKeySlotId, create_test_crypto_with_user_key,
    };
    use bitwarden_crypto::{Decryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm};

    use super::*;
    use crate::{
        LoginUriView, LoginView, PasswordHistoryView,
        cipher::{CipherRepromptType, blob::try_parse_blob},
    };

    fn key_store() -> KeyStore<KeySlotIds> {
        create_test_crypto_with_user_key(SymmetricCryptoKey::make(
            SymmetricKeyAlgorithm::Aes256CbcHmac,
        ))
    }

    fn login_view() -> CipherView {
        CipherView {
            partial: false,
            r#type: CipherType::Login,
            login: Some(LoginView {
                username: Some("user".to_string()),
                password: Some("old-password".to_string()),
                password_revision_date: None,
                uris: Some(vec![LoginUriView {
                    uri: Some("https://example.com".to_string()),
                    r#match: None,
                    uri_checksum: None,
                }]),
                totp: None,
                autofill_on_page_load: None,
                http_authentication_enabled: None,
                fido2_credentials: None,
            }),
            id: Some("fd411a1a-fec8-4070-985d-0e6560860e69".parse().unwrap()),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: "My login".to_string(),
            notes: None,
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
            password_history: None,
            creation_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            archived_date: None,
        }
    }

    fn encrypt(key_store: &KeyStore<KeySlotIds>, view: CipherView) -> Cipher {
        key_store.encrypt(EncryptMode::Legacy(view)).unwrap()
    }

    #[test]
    fn changes_password_and_keeps_other_fields() {
        let key_store = key_store();
        let cipher = encrypt(&key_store, login_view());

        let changed = cipher
            .change_login_password(&key_store, "new-password")
            .unwrap();

        let view: CipherView = key_store.decrypt(&changed).unwrap();
        let login = view.login.unwrap();
        assert_eq!(login.password.as_deref(), Some("new-password"));
        assert_eq!(login.username.as_deref(), Some("user"));
        assert_eq!(
            login.uris.unwrap()[0].uri.as_deref(),
            Some("https://example.com")
        );
        assert_eq!(view.name, "My login");
    }

    #[test]
    fn records_old_password_in_history() {
        let key_store = key_store();
        let mut view = login_view();
        view.password_history = Some(vec![PasswordHistoryView {
            password: "older-password".to_string(),
            last_used_date: "2024-01-01T00:00:00Z".parse().unwrap(),
        }]);
        let cipher = encrypt(&key_store, view);

        let changed = cipher
            .change_login_password(&key_store, "new-password")
            .unwrap();

        let view: CipherView = key_store.decrypt(&changed).unwrap();
        let history = view.password_history.unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].password, "old-password");
        assert_eq!(history[1].password, "older-password");
        assert!(view.login.unwrap().password_revision_date.is_some());
    }

    #[test]
    fn keeps_legacy_format_below_blob_version() {
        let key_store = key_store();
        let cipher = encrypt(&key_store, login_view());

        let changed = cipher
            .change_login_password(&key_store, "new-password")
            .unwrap();

        assert!(try_parse_blob(&changed).is_none());
    }

    #[test]
    fn uses_blob_format_at_blob_version() {
        let key_store = key_store();
        key_store.set_security_state_version(BLOB_SECURITY_VERSION);
        let cipher = key_store.encrypt(EncryptMode::Blob(login_view())).unwrap();

        let changed = cipher
            .change_login_password(&key_store, "new-password")
            .unwrap();

        assert!(try_parse_blob(&changed).is_some());
        let view: CipherView = key_store.decrypt(&changed).unwrap();
        assert_eq!(
            view.login.unwrap().password.as_deref(),
            Some("new-password")
        );
        assert_eq!(view.password_history.unwrap()[0].password, "old-password");
    }

    #[test]
    fn keeps_the_item_key() {
        let key_store = key_store();
        let cipher = encrypt(&key_store, login_view());
        let original_key = cipher.key.clone().expect("item key is generated");

        let changed = cipher
            .change_login_password(&key_store, "new-password")
            .unwrap();

        // The result's fields decrypt under the original item key.
        let mut ctx = key_store.context();
        let item_key = ctx
            .unwrap_symmetric_key(SymmetricKeySlotId::User, &original_key)
            .unwrap();
        let name: String = changed.name.unwrap().decrypt(&mut ctx, item_key).unwrap();
        assert_eq!(name, "My login");
    }

    #[test]
    fn refuses_non_login_cipher() {
        let key_store = key_store();
        let mut view = login_view();
        view.r#type = CipherType::SecureNote;
        view.login = None;
        let cipher = encrypt(&key_store, view);

        let result = cipher.change_login_password(&key_store, "new-password");

        assert!(matches!(result, Err(ChangeLoginPasswordError::NotLogin)));
    }

    #[test]
    fn refuses_partial_cipher() {
        let key_store = key_store();
        let mut cipher = encrypt(&key_store, login_view());
        cipher.partial_data = Some("{}".to_string());

        let result = cipher.change_login_password(&key_store, "new-password");

        assert!(matches!(
            result,
            Err(ChangeLoginPasswordError::PartialCipher)
        ));
    }

    #[test]
    fn refuses_cipher_with_undecryptable_field() {
        let key_store = key_store();
        let other_store = create_test_crypto_with_user_key(SymmetricCryptoKey::make(
            SymmetricKeyAlgorithm::Aes256CbcHmac,
        ));
        let mut cipher = encrypt(&key_store, login_view());
        // Password encrypted under an unrelated key, so it cannot decrypt here.
        let foreign = encrypt(&other_store, login_view());
        cipher.login.as_mut().unwrap().password = foreign.login.unwrap().password;

        let result = cipher.change_login_password(&key_store, "new-password");

        assert!(matches!(result, Err(ChangeLoginPasswordError::Crypto(_))));
    }
}
