//! Functionality for re-encrypting user data during key rotation.

use bitwarden_api_api::models::{
    AccountDataRequestModel, CipherWithIdRequestModel, SendWithIdRequestModel,
};
use bitwarden_core::{
    UserId,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};
use bitwarden_crypto::{CompositeEncryptable, Decryptable, KeyStoreContext};
use bitwarden_send::SendView;
use bitwarden_vault::{CipherView, EncryptMode, EncryptionContext, FolderView};
use tracing::{debug, debug_span};
use uuid::Uuid;

use super::RotateUserKeysError;

/// Errors that can occur during data re-encryption
#[derive(Debug)]
pub(crate) enum DataReencryptionError {
    /// Failed to decrypt data with the current user key
    Decryption,
    /// Failed to encrypt data with the new user key
    Encryption,
    /// Failed to convert data to API model
    DataConversion,
    /// CipherKeyRewrap
    CipherKeyRewrap,
}

/// Checks that no cipher contains legacy attachments (attachments where `key` is `None`).
/// Ciphers with old attachments cannot be safely re-encrypted during key rotation because
/// the attachment file contents are encrypted directly with the user key and would become
/// irrecoverable after the user key change.
pub(super) fn check_for_old_attachments(
    ciphers: &[bitwarden_vault::Cipher],
) -> Result<(), RotateUserKeysError> {
    let has_old = ciphers
        .iter()
        .filter(|c| c.organization_id.is_none())
        .any(|c| {
            c.attachments
                .as_ref()
                .is_some_and(|atts| atts.iter().any(|a| a.key.is_none()))
        });
    if has_old {
        return Err(RotateUserKeysError::OldAttachments);
    }
    Ok(())
}

/// Re-encrypts all user data (folders, ciphers, sends) with the new user key for the purpose of
/// key-rotation. Note: Ciphers must be filtered to just contain the user's ciphers, not
/// organization ciphers.
#[bitwarden_logging::instrument(name = "reencrypt_data", fields(current_user_key_id = ?current_user_key_id, new_user_key_id = ?new_user_key_id))]
pub(super) fn reencrypt_data(
    folders: &[bitwarden_vault::Folder],
    ciphers: &[bitwarden_vault::Cipher],
    sends: &[bitwarden_send::Send],
    current_user_key_id: SymmetricKeySlotId,
    new_user_key_id: SymmetricKeySlotId,
    ctx: &mut KeyStoreContext<KeySlotIds>,
) -> Result<AccountDataRequestModel, DataReencryptionError> {
    // Fully re-encrypt all user data with the new user key
    let reencrypted_folders =
        reencrypt_folders(folders, current_user_key_id, new_user_key_id, ctx)?;
    let reencrypted_ciphers =
        reencrypt_ciphers(ciphers, current_user_key_id, new_user_key_id, ctx)?;
    let reencrypted_sends = reencrypt_sends(sends, current_user_key_id, new_user_key_id, ctx)?;
    Ok(AccountDataRequestModel {
        folders: Some(
            reencrypted_folders
                .into_iter()
                .map(|folder| (&folder).into())
                .collect(),
        ),
        ciphers: Some(
            reencrypted_ciphers
                .into_iter()
                .map(|cipher| {
                    EncryptionContext {
                        // Encrypted for is not used in key-rotation, and ciphers are validated to
                        // be correct server-side
                        encrypted_for: UserId::new(Uuid::nil()),
                        cipher,
                    }
                    .try_into()
                    .map_err(|_| DataReencryptionError::DataConversion)
                })
                .collect::<Result<Vec<CipherWithIdRequestModel>, DataReencryptionError>>()?,
        ),
        sends: Some(
            reencrypted_sends
                .into_iter()
                .map(|send| Ok(send.into()))
                .collect::<Result<Vec<SendWithIdRequestModel>, DataReencryptionError>>()?,
        ),
    })
}

#[bitwarden_logging::instrument(name = "reencrypt_folders", fields(current_key = ?current_key, new_key = ?new_key))]
fn reencrypt_folders(
    folders: &[bitwarden_vault::Folder],
    current_key: SymmetricKeySlotId,
    new_key: SymmetricKeySlotId,
    ctx: &mut KeyStoreContext<KeySlotIds>,
) -> Result<Vec<bitwarden_vault::Folder>, DataReencryptionError> {
    folders
        .iter()
        .map(|folder| {
            let _span = debug_span!("reencrypt_folder", folder_id = ?folder.id).entered();
            let folder_view: FolderView = folder
                .decrypt(ctx, current_key)
                .map_err(|_| DataReencryptionError::Decryption)?;
            folder_view
                .encrypt_composite(ctx, new_key)
                .map_err(|_| DataReencryptionError::Encryption)
        })
        .collect::<Result<Vec<bitwarden_vault::Folder>, DataReencryptionError>>()
}

#[bitwarden_logging::instrument(name = "reencrypt_ciphers", fields(current_key = ?current_key, new_key = ?new_key))]
fn reencrypt_ciphers(
    ciphers: &[bitwarden_vault::Cipher],
    current_key: SymmetricKeySlotId,
    new_key: SymmetricKeySlotId,
    ctx: &mut KeyStoreContext<KeySlotIds>,
) -> Result<Vec<bitwarden_vault::Cipher>, DataReencryptionError> {
    ciphers
        .iter()
        .map(|cipher| {
            let _span = debug_span!("reencrypt_cipher", cipher_id = ?cipher.id).entered();

            // Rotation always lands the account on the V2 security state, so every individual
            // cipher ends up blob-encrypted. Ciphers that are already sealed blobs only need their
            // per-item key re-wrapped; the sealed blob is left untouched. Legacy ciphers are
            // decrypted and re-sealed as blobs.
            if cipher.is_blob_encrypted() && cipher.key.is_some() {
                debug!("Cipher already blob-encrypted, re-wrapping cipher key");
                let mut cipher = cipher.clone();
                cipher
                    .rewrap_cipher_key(current_key, new_key, ctx)
                    .map_err(|_| DataReencryptionError::CipherKeyRewrap)?;
                Ok(cipher)
            } else {
                debug!("Upgrading legacy cipher to blob encryption");
                let cipher_view = decrypt_for_blob_upgrade(cipher, current_key, new_key, ctx)?;
                EncryptMode::Blob(cipher_view)
                    .encrypt_composite(ctx, new_key)
                    .map_err(|_| DataReencryptionError::Encryption)
            }
        })
        .collect::<Result<Vec<bitwarden_vault::Cipher>, DataReencryptionError>>()
}

/// Decrypts a legacy cipher into a view ready to be re-sealed as a blob under `new_key`.
///
/// The returned view carries a per-item cipher key wrapped under `new_key`, with its sub-keys
/// (attachment keys, FIDO2 credentials) wrapped under that cipher key.
fn decrypt_for_blob_upgrade(
    cipher: &bitwarden_vault::Cipher,
    current_key: SymmetricKeySlotId,
    new_key: SymmetricKeySlotId,
    ctx: &mut KeyStoreContext<KeySlotIds>,
) -> Result<CipherView, DataReencryptionError> {
    if cipher.key.is_some() {
        let mut rewrapped = cipher.clone();
        rewrapped
            .rewrap_cipher_key(current_key, new_key, ctx)
            .map_err(|_| DataReencryptionError::CipherKeyRewrap)?;
        rewrapped
            .decrypt(ctx, new_key)
            .map_err(|_| DataReencryptionError::Decryption)
    } else {
        let mut view: CipherView = cipher
            .decrypt(ctx, current_key)
            .map_err(|_| DataReencryptionError::Decryption)?;
        view.upgrade_to_cipher_key_encryption_with_external_key(ctx, current_key, new_key)
            .map_err(|_| DataReencryptionError::Encryption)?;
        Ok(view)
    }
}

#[bitwarden_logging::instrument(name = "reencrypt_sends", fields(current_key = ?current_key, new_key = ?new_key))]
fn reencrypt_sends(
    sends: &[bitwarden_send::Send],
    current_key: SymmetricKeySlotId,
    new_key: SymmetricKeySlotId,
    ctx: &mut KeyStoreContext<KeySlotIds>,
) -> Result<Vec<bitwarden_send::Send>, DataReencryptionError> {
    sends
        .iter()
        .map(|send| {
            let _span = debug_span!("reencrypt_send", send_id = ?send.id).entered();
            let send_view: SendView = send
                .decrypt(ctx, current_key)
                .map_err(|_| DataReencryptionError::Decryption)?;
            send_view
                .encrypt_composite(ctx, new_key)
                .map_err(|_| DataReencryptionError::Encryption)
        })
        .collect::<Result<Vec<bitwarden_send::Send>, DataReencryptionError>>()
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
    use bitwarden_crypto::{CompositeEncryptable, Decryptable, KeyStore, PrimitiveEncryptable};
    use bitwarden_send::SendView;
    use bitwarden_vault::{
        Attachment, Cipher, CipherRepromptType, CipherType, CipherView, EncryptMode,
        Fido2CredentialFullView,
    };
    use chrono::Utc;

    use super::check_for_old_attachments;
    use crate::key_rotation::RotateUserKeysError;

    const TEST_ENC_STRING: &str = "2.STIyTrfDZN/JXNDN9zNEMw==|NDLum8BHZpPNYhJo9ggSkg==|UCsCLlBO3QzdPwvMAWs2VVwuE6xwOx/vxOooPObqnEw=";

    fn make_test_cipher(attachments: Option<Vec<Attachment>>) -> Cipher {
        Cipher {
            id: None,
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: Some(TEST_ENC_STRING.parse().unwrap()),
            notes: None,
            r#type: CipherType::Login,
            login: None,
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            bank_account: None,
            passport: None,
            drivers_license: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: false,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments,
            fields: None,
            password_history: None,
            creation_date: "2024-01-01T00:00:00Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-01-01T00:00:00Z".parse().unwrap(),
            archived_date: None,
            data: None,
        }
    }

    #[test]
    fn test_check_for_old_attachments_no_attachments() {
        let ciphers = vec![make_test_cipher(None)];
        assert!(check_for_old_attachments(&ciphers).is_ok());
    }

    #[test]
    fn test_check_for_old_attachments_empty_ciphers() {
        assert!(check_for_old_attachments(&[]).is_ok());
    }

    #[test]
    fn test_check_for_old_attachments_all_have_keys() {
        let ciphers = vec![make_test_cipher(Some(vec![Attachment {
            id: Some("att1".to_string()),
            url: None,
            size: None,
            size_name: None,
            file_name: Some(TEST_ENC_STRING.parse().unwrap()),
            key: Some(TEST_ENC_STRING.parse().unwrap()),
        }]))];
        assert!(check_for_old_attachments(&ciphers).is_ok());
    }

    #[test]
    fn test_check_for_old_attachments_one_missing_key() {
        let ciphers = vec![make_test_cipher(Some(vec![Attachment {
            id: Some("att1".to_string()),
            url: None,
            size: None,
            size_name: None,
            file_name: Some(TEST_ENC_STRING.parse().unwrap()),
            key: None,
        }]))];
        assert!(matches!(
            check_for_old_attachments(&ciphers),
            Err(RotateUserKeysError::OldAttachments)
        ));
    }

    #[test]
    fn test_check_for_old_attachments_ignores_organization_ciphers() {
        let mut cipher = make_test_cipher(Some(vec![Attachment {
            id: Some("att1".to_string()),
            url: None,
            size: None,
            size_name: None,
            file_name: Some(TEST_ENC_STRING.parse().unwrap()),
            key: None,
        }]));
        cipher.organization_id = Some(bitwarden_core::OrganizationId::new_v4());
        let ciphers = vec![cipher];
        assert!(check_for_old_attachments(&ciphers).is_ok());
    }

    fn make_cipher_view() -> bitwarden_vault::CipherView {
        use bitwarden_vault::{CipherView, LoginView};
        CipherView {
            id: None,
            organization_id: None,
            folder_id: None,
            r#type: CipherType::Login,
            name: "Test Cipher".to_string(),
            notes: Some("Some cipher notes".to_string()),
            favorite: false,
            revision_date: Utc::now(),
            deleted_date: None,
            fields: None,
            login: Some(LoginView {
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
                totp: None,
                uris: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
                password_revision_date: None,
            }),
            card: None,
            identity: None,
            secure_note: None,
            attachments: None,
            attachment_decryption_failures: None,
            organization_use_totp: false,
            collection_ids: vec![],
            reprompt: CipherRepromptType::None,
            local_data: None,
            key: None,
            ssh_key: None,
            bank_account: None,
            passport: None,
            drivers_license: None,
            permissions: None,
            view_password: false,
            creation_date: Utc::now(),
            archived_date: None,
            edit: false,
            password_history: None,
        }
    }

    fn assert_decrypts_to(
        cipher: &Cipher,
        expected: &CipherView,
        key: SymmetricKeySlotId,
        ctx: &mut bitwarden_crypto::KeyStoreContext<KeySlotIds>,
    ) {
        use bitwarden_vault::CipherView;
        let decrypted: CipherView = cipher.decrypt(ctx, key).unwrap();
        assert_eq!(expected.name, decrypted.name);
        assert_eq!(expected.notes, decrypted.notes);
        assert_eq!(expected.r#type, decrypted.r#type);
        assert_eq!(
            expected.login.as_ref().unwrap().username,
            decrypted.login.as_ref().unwrap().username
        );
        assert_eq!(
            expected.login.as_ref().unwrap().password,
            decrypted.login.as_ref().unwrap().password
        );
    }

    #[test]
    fn test_blob_gate_rewraps_existing_blob_without_re_encrypting() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        let user_key_old =
            ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac);
        let user_key_new =
            ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // An already blob-encrypted cipher
        let cipher = make_cipher_view();
        let encrypted = EncryptMode::Blob(cipher.clone())
            .encrypt_composite(&mut ctx, user_key_old)
            .unwrap();
        assert!(encrypted.is_blob_encrypted());

        let reencrypted = super::reencrypt_ciphers(
            std::slice::from_ref(&encrypted),
            user_key_old,
            user_key_new,
            &mut ctx,
        )
        .unwrap();

        // The sealed blob is left intact; only the wrapped cipher key is rewrapped
        assert!(reencrypted[0].is_blob_encrypted());
        assert_eq!(encrypted.data, reencrypted[0].data);
        assert_ne!(encrypted.key, reencrypted[0].key);
        assert_decrypts_to(&reencrypted[0], &cipher, user_key_new, &mut ctx);
    }

    #[test]
    fn test_folders() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        let user_key_old =
            ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac);
        let user_key_new =
            ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac);

        // Create an encrypted folder
        let folder = bitwarden_vault::FolderView {
            id: None,
            name: "Test Folder".to_string(),
            revision_date: Utc::now(),
        };
        let encrypted_folder = folder.encrypt_composite(&mut ctx, user_key_old).unwrap();

        // Rotate it
        let folders = vec![encrypted_folder];
        let reencrypted_folders =
            super::reencrypt_folders(folders.as_slice(), user_key_old, user_key_new, &mut ctx)
                .unwrap();

        // Decrypt and assert
        let decrypted_folder = reencrypted_folders[0]
            .decrypt(&mut ctx, user_key_new)
            .unwrap();
        assert_eq!(folder, decrypted_folder);
    }

    #[test]
    fn test_sends() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        let user_key_old =
            ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac);
        let user_key_new =
            ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac);

        // Create an encrypted send
        let send = bitwarden_send::SendView {
            id: None,
            access_id: None,
            name: "Test Send".to_string(),
            notes: Some("Some notes".to_string()),
            key: Some("Pgui0FK85cNhBGWHAlBHBw".to_owned()),
            text: Some(bitwarden_send::SendTextView {
                text: Some("This is a test send".to_string()),
                hidden: false,
            }),
            r#type: bitwarden_send::SendType::Text,
            max_access_count: None,
            access_count: 0,
            disabled: false,
            hide_email: false,
            revision_date: Utc::now(),
            deletion_date: Utc::now(),
            expiration_date: None,
            new_password: None,
            has_password: false,
            file: None,
            emails: vec![],
            auth_type: bitwarden_send::AuthType::None,
        };
        let encrypted_send = send.encrypt_composite(&mut ctx, user_key_old).unwrap();

        // Rotate it
        let sends = vec![encrypted_send];
        let reencrypted_sends =
            super::reencrypt_sends(sends.as_slice(), user_key_old, user_key_new, &mut ctx).unwrap();

        // Decrypt and assert
        let decrypted_send: SendView = reencrypted_sends[0]
            .decrypt(&mut ctx, user_key_new)
            .unwrap();

        // The send seed must be the same
        assert_eq!(send.key, decrypted_send.key);
    }

    #[test]
    fn test_rotation_keyless_plain() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (old, new) = make_rotation_keys(&mut ctx);

        let cipher = make_rotatable_cipher(&mut ctx, old, false, false, false);
        let out = super::reencrypt_ciphers(&[cipher], old, new, &mut ctx).unwrap();

        assert_upgraded_to_blob(&mut ctx, &out[0], new);
    }

    #[test]
    fn test_rotation_keyless_fido2() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (old, new) = make_rotation_keys(&mut ctx);

        let cipher = make_rotatable_cipher(&mut ctx, old, false, false, true);
        let out = super::reencrypt_ciphers(&[cipher], old, new, &mut ctx).unwrap();

        assert_upgraded_to_blob(&mut ctx, &out[0], new);
        assert_fido2_decryptable(&mut ctx, &out[0], new);
    }

    #[test]
    fn test_rotation_keyless_attachment() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (old, new) = make_rotation_keys(&mut ctx);

        let cipher = make_rotatable_cipher(&mut ctx, old, false, true, false);
        let out = super::reencrypt_ciphers(&[cipher], old, new, &mut ctx).unwrap();

        assert_upgraded_to_blob(&mut ctx, &out[0], new);
        assert_attachment_key_decryptable(&mut ctx, &out[0], new);
    }

    #[test]
    fn test_rotation_keyless_fido2_and_attachment() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (old, new) = make_rotation_keys(&mut ctx);

        let cipher = make_rotatable_cipher(&mut ctx, old, false, true, true);
        let out = super::reencrypt_ciphers(&[cipher], old, new, &mut ctx).unwrap();

        assert_upgraded_to_blob(&mut ctx, &out[0], new);
        assert_fido2_decryptable(&mut ctx, &out[0], new);
        assert_attachment_key_decryptable(&mut ctx, &out[0], new);
    }

    #[test]
    fn test_rotation_keyed_plain() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (old, new) = make_rotation_keys(&mut ctx);

        let cipher = make_rotatable_cipher(&mut ctx, old, true, false, false);
        let out = super::reencrypt_ciphers(&[cipher], old, new, &mut ctx).unwrap();

        assert_upgraded_to_blob(&mut ctx, &out[0], new);
    }

    #[test]
    fn test_rotation_keyed_fido2() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (old, new) = make_rotation_keys(&mut ctx);

        let cipher = make_rotatable_cipher(&mut ctx, old, true, false, true);
        let out = super::reencrypt_ciphers(&[cipher], old, new, &mut ctx).unwrap();

        assert_upgraded_to_blob(&mut ctx, &out[0], new);
        assert_fido2_decryptable(&mut ctx, &out[0], new);
    }

    #[test]
    fn test_rotation_keyed_attachment() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (old, new) = make_rotation_keys(&mut ctx);

        let cipher = make_rotatable_cipher(&mut ctx, old, true, true, false);
        let out = super::reencrypt_ciphers(&[cipher], old, new, &mut ctx).unwrap();

        assert_upgraded_to_blob(&mut ctx, &out[0], new);
        assert_attachment_key_decryptable(&mut ctx, &out[0], new);
    }

    #[test]
    fn test_rotation_keyed_fido2_and_attachment() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (old, new) = make_rotation_keys(&mut ctx);

        let cipher = make_rotatable_cipher(&mut ctx, old, true, true, true);
        let out = super::reencrypt_ciphers(&[cipher], old, new, &mut ctx).unwrap();

        assert_upgraded_to_blob(&mut ctx, &out[0], new);
        assert_fido2_decryptable(&mut ctx, &out[0], new);
        assert_attachment_key_decryptable(&mut ctx, &out[0], new);
    }

    /// The old and new user keys for a rotation: two distinct non-`User` slots (so the rotation
    /// must honor the explicit keys rather than the cipher's `key_identifier()`), with a change of
    /// algorithm mirroring production, which rotates onto an XChaCha20-Poly1305 key.
    fn make_rotation_keys(
        ctx: &mut bitwarden_crypto::KeyStoreContext<KeySlotIds>,
    ) -> (SymmetricKeySlotId, SymmetricKeySlotId) {
        let old = ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac);
        let new =
            ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::XChaCha20Poly1305);
        (old, new)
    }

    /// Builds a legacy personal cipher encrypted under `user_key`, optionally carrying a per-item
    /// cipher key, an attachment, and a FIDO2 credential.
    fn make_rotatable_cipher(
        ctx: &mut bitwarden_crypto::KeyStoreContext<KeySlotIds>,
        user_key: SymmetricKeySlotId,
        with_cipher_key: bool,
        with_attachment: bool,
        with_fido2: bool,
    ) -> Cipher {
        let mut view = make_cipher_view();
        if with_fido2 {
            let full = Fido2CredentialFullView {
                credential_id: "cred-123".to_string(),
                key_type: "public-key".to_string(),
                key_algorithm: "ECDSA".to_string(),
                key_curve: "P-256".to_string(),
                key_value: "key-value".to_string(),
                rp_id: "example.com".to_string(),
                user_handle: None,
                user_name: None,
                counter: "0".to_string(),
                rp_name: None,
                user_display_name: None,
                discoverable: "true".to_string(),
                creation_date: "2024-06-07T14:12:36.150Z".parse().unwrap(),
            };
            view.login.as_mut().unwrap().fido2_credentials =
                Some(vec![full.encrypt_composite(ctx, user_key).unwrap()]);
        }
        if with_cipher_key {
            view.upgrade_to_cipher_key_encryption_with_external_key(ctx, user_key, user_key)
                .unwrap();
        }
        let mut cipher = EncryptMode::Legacy(view)
            .encrypt_composite(ctx, user_key)
            .unwrap();
        if with_attachment {
            // The attachment content key and file name are wrapped under the cipher key: the
            // per-item key for a keyed cipher, otherwise the user key directly.
            let cipher_key = match &cipher.key {
                Some(key) => ctx.unwrap_symmetric_key(user_key, key).unwrap(),
                None => user_key,
            };
            let content_key = ctx.generate_symmetric_key();
            cipher.attachments = Some(vec![Attachment {
                id: Some("att1".to_string()),
                url: None,
                size: None,
                size_name: None,
                file_name: Some("secret.txt".encrypt(ctx, cipher_key).unwrap()),
                key: Some(ctx.wrap_symmetric_key(cipher_key, content_key).unwrap()),
            }]);
        }
        cipher
    }

    /// Asserts the rotated cipher is a blob whose body decrypts under `user_key` to the baseline
    /// [`make_cipher_view`] fields.
    fn assert_upgraded_to_blob(
        ctx: &mut bitwarden_crypto::KeyStoreContext<KeySlotIds>,
        rotated: &Cipher,
        user_key: SymmetricKeySlotId,
    ) {
        assert!(rotated.is_blob_encrypted());
        assert_decrypts_to(rotated, &make_cipher_view(), user_key, ctx);
    }

    /// Asserts the rotated cipher's FIDO2 credential decrypts to its original values under
    /// `user_key`.
    fn assert_fido2_decryptable(
        ctx: &mut bitwarden_crypto::KeyStoreContext<KeySlotIds>,
        rotated: &Cipher,
        user_key: SymmetricKeySlotId,
    ) {
        let dv: CipherView = rotated.decrypt(ctx, user_key).unwrap();
        let cipher_key = ctx
            .unwrap_symmetric_key(user_key, dv.key.as_ref().unwrap())
            .unwrap();
        let creds: Vec<Fido2CredentialFullView> = dv
            .login
            .as_ref()
            .unwrap()
            .fido2_credentials
            .as_ref()
            .unwrap()
            .decrypt(ctx, cipher_key)
            .unwrap();
        assert_eq!(creds[0].credential_id, "cred-123");
        assert_eq!(creds[0].key_value, "key-value");
    }

    /// Asserts the rotated cipher's attachment key unwraps under `user_key`.
    fn assert_attachment_key_decryptable(
        ctx: &mut bitwarden_crypto::KeyStoreContext<KeySlotIds>,
        rotated: &Cipher,
        user_key: SymmetricKeySlotId,
    ) {
        let dv: CipherView = rotated.decrypt(ctx, user_key).unwrap();
        let cipher_key = ctx
            .unwrap_symmetric_key(user_key, dv.key.as_ref().unwrap())
            .unwrap();
        let att = &dv.attachments.as_ref().unwrap()[0];
        assert_eq!(att.file_name.as_deref(), Some("secret.txt"));
        let _ = ctx
            .unwrap_symmetric_key(cipher_key, att.key.as_ref().unwrap())
            .expect("attachment key must unwrap under the new cipher key");
    }
}
