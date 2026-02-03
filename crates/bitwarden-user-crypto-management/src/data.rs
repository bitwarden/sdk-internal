//! Functionality for re-encrypting user data during key rotation.

use bitwarden_api_api::models::{
    AccountDataRequestModel, CipherWithIdRequestModel, SendWithIdRequestModel,
};
use bitwarden_core::{
    UserId,
    key_management::{KeyIds, SymmetricKeyId},
};
use bitwarden_crypto::{CompositeEncryptable, Decryptable, KeyStoreContext};
use bitwarden_send::SendView;
use bitwarden_vault::{CipherView, EncryptionContext, FolderView};
use tracing::{debug_span, instrument};
use uuid::Uuid;

/// Errors that can occur during data re-encryption
#[derive(Debug)]
pub(crate) enum DataReencryptionError {
    /// Failed to decrypt data with the current user key
    Decryption,
    /// Failed to encrypt data with the new user key
    Encryption,
    /// Failed to convert data to API model
    DataConversion,
}

#[allow(unused)]
#[instrument(name = "reencrypt_data", skip(folders, cipher, sends, ctx))]
pub(super) fn reencrypt_data(
    folders: &[bitwarden_vault::Folder],
    cipher: &[bitwarden_vault::Cipher],
    sends: &[bitwarden_send::Send],
    current_user_key_id: SymmetricKeyId,
    new_user_key_id: SymmetricKeyId,
    ctx: &mut KeyStoreContext<KeyIds>,
) -> Result<AccountDataRequestModel, DataReencryptionError> {
    // Fully re-encrypt all user data with the new user key
    let reencrypted_folders =
        reencrypt_folders(folders, current_user_key_id, new_user_key_id, ctx)?;
    let reencrypted_ciphers = reencrypt_ciphers(cipher, current_user_key_id, new_user_key_id, ctx)?;
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
                .map(|send| {
                    Ok(SendWithIdRequestModel {
                        id: send.id.ok_or(DataReencryptionError::DataConversion)?,
                        key: send.key.to_string(),
                        // During key-rotation only the "key" (encrypted seed) and id are used, since we only
                        // re-encrypt the "key"
                        ..Default::default()
                    })
                })
                .collect::<Result<Vec<SendWithIdRequestModel>, DataReencryptionError>>()?,
        ),
    })
}

#[instrument(name = "reencrypt_folders", skip(folders, ctx))]
fn reencrypt_folders(
    folders: &[bitwarden_vault::Folder],
    current_key: SymmetricKeyId,
    new_key: SymmetricKeyId,
    ctx: &mut KeyStoreContext<KeyIds>,
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

#[instrument(name = "reencrypt_ciphers", skip(ciphers, ctx))]
fn reencrypt_ciphers(
    ciphers: &[bitwarden_vault::Cipher],
    current_key: SymmetricKeyId,
    new_key: SymmetricKeyId,
    ctx: &mut KeyStoreContext<KeyIds>,
) -> Result<Vec<bitwarden_vault::Cipher>, DataReencryptionError> {
    ciphers
        .iter()
        .map(|cipher| {
            let _span = debug_span!("reencrypt_cipher", cipher_id = ?cipher.id).entered();
            let cipher_view: CipherView = cipher
                .decrypt(ctx, current_key)
                .map_err(|_| DataReencryptionError::Decryption)?;
            cipher_view
                .encrypt_composite(ctx, new_key)
                .map_err(|_| DataReencryptionError::Encryption)
        })
        .collect::<Result<Vec<bitwarden_vault::Cipher>, DataReencryptionError>>()
}

#[instrument(name = "reencrypt_sends", skip(sends, ctx))]
fn reencrypt_sends(
    sends: &[bitwarden_send::Send],
    current_key: SymmetricKeyId,
    new_key: SymmetricKeyId,
    ctx: &mut KeyStoreContext<KeyIds>,
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
    use bitwarden_core::key_management::KeyIds;
    use bitwarden_crypto::{CompositeEncryptable, Decryptable, KeyStore};
    use bitwarden_send::SendView;
    use chrono::Utc;

    #[test]
    fn test_ciphers() {
        use bitwarden_vault::{CipherType, CipherView, LoginView};
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        let user_key_old =
            ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac);
        let user_key_new =
            ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac);

        let cipher = CipherView {
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
            reprompt: bitwarden_vault::CipherRepromptType::None,
            local_data: None,
            key: None,
            ssh_key: None,
            permissions: None,
            view_password: false,
            creation_date: Utc::now(),
            archived_date: None,
            edit: false,
            password_history: None,
        };
        let encrypted_cipher = cipher.encrypt_composite(&mut ctx, user_key_old).unwrap();

        // Rotate it
        let ciphers = vec![encrypted_cipher];
        let reencrypted_ciphers =
            super::reencrypt_ciphers(ciphers.as_slice(), user_key_old, user_key_new, &mut ctx)
                .unwrap();

        // Decrypt and assert
        let decrypted_cipher: CipherView = reencrypted_ciphers[0]
            .decrypt(&mut ctx, user_key_new)
            .unwrap();
        assert_eq!(cipher.name, decrypted_cipher.name);
        assert_eq!(cipher.notes, decrypted_cipher.notes);
        assert_eq!(cipher.r#type, decrypted_cipher.r#type);
        assert_eq!(
            cipher.login.as_ref().unwrap().username,
            decrypted_cipher.login.as_ref().unwrap().username
        );
        assert_eq!(
            cipher.login.as_ref().unwrap().password,
            decrypted_cipher.login.as_ref().unwrap().password
        );
    }

    #[test]
    fn test_folders() {
        let store: KeyStore<KeyIds> = KeyStore::default();
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
        let store: KeyStore<KeyIds> = KeyStore::default();
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
}
