use bitwarden_core::key_management::KeyIds;
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, IdentifyKey, KeyStoreContext, PrimitiveEncryptable,
};
use thiserror::Error;

use super::{CipherBlob, CipherBlobLatest, SealedCipherBlob, SealedCipherBlobError};
use crate::cipher::cipher::{Cipher, CipherView};

#[derive(Debug, Error)]
pub(crate) enum BlobEncryptionError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    SealedBlob(#[from] SealedCipherBlobError),
    #[error("Cipher does not contain blob data")]
    NoBlobData,
}

/// Returns `true` if the cipher's `data` field contains a valid sealed blob.
pub(crate) fn is_blob_encrypted(cipher: &Cipher) -> bool {
    cipher
        .data
        .as_ref()
        .is_some_and(|s| SealedCipherBlob::from_opaque_string(s).is_ok())
}

/// Returns `true` if the cipher is not blob-encrypted (i.e. uses legacy field-level encryption).
pub(crate) fn is_legacy_cipher(cipher: &Cipher) -> bool {
    !is_blob_encrypted(cipher)
}

/// Seals a `CipherView` into an opaque blob string.
pub(crate) fn seal_cipher(
    view: &CipherView,
    ctx: &mut KeyStoreContext<KeyIds>,
) -> Result<String, BlobEncryptionError> {
    let outer_key = view.key_identifier();
    let cipher_key = Cipher::decrypt_cipher_key(ctx, outer_key, &view.key)?;

    let blob = CipherBlobLatest::from_cipher_view(view, ctx, cipher_key)?;
    let versioned: CipherBlob = blob.into();
    let sealed = SealedCipherBlob::seal(versioned, &cipher_key, ctx)?;
    Ok(sealed.to_opaque_string()?)
}

/// Unseals a cipher's blob data, returning the latest blob version.
pub(crate) fn unseal_cipher(
    cipher: &Cipher,
    ctx: &mut KeyStoreContext<KeyIds>,
) -> Result<CipherBlobLatest, BlobEncryptionError> {
    let outer_key = cipher.key_identifier();
    let cipher_key = Cipher::decrypt_cipher_key(ctx, outer_key, &cipher.key)?;

    let data = cipher
        .data
        .as_ref()
        .ok_or(BlobEncryptionError::NoBlobData)?;
    let sealed = SealedCipherBlob::from_opaque_string(data)?;
    let blob = sealed.unseal(&cipher_key, ctx)?;

    match blob {
        CipherBlob::CipherBlobV1(v1) => Ok(v1),
    }
}

/// Creates a blob-encrypted `Cipher` from a `CipherView`.
///
/// Generates a cipher key if missing, seals the sensitive data into a single blob,
/// and encrypts attachments and local data separately.
pub(crate) fn create_blob_cipher(
    view: &mut CipherView,
    ctx: &mut KeyStoreContext<KeyIds>,
) -> Result<Cipher, BlobEncryptionError> {
    if view.key.is_none() {
        view.generate_cipher_key(ctx, view.key_identifier())?;
    }

    let outer_key = view.key_identifier();
    let cipher_key = Cipher::decrypt_cipher_key(ctx, outer_key, &view.key)?;

    let sealed_string = seal_cipher(view, ctx)?;

    let attachments = view.attachments.encrypt_composite(ctx, cipher_key)?;
    let local_data = view.local_data.encrypt_composite(ctx, cipher_key)?;

    // TODO: Remove this field once the server no longer requires it
    let name = "".encrypt(ctx, cipher_key)?;

    Ok(Cipher {
        id: view.id,
        organization_id: view.organization_id,
        folder_id: view.folder_id,
        collection_ids: view.collection_ids.clone(),
        key: view.key.clone(),
        name,
        notes: None,
        r#type: view.r#type,
        login: None,
        identity: None,
        card: None,
        secure_note: None,
        ssh_key: None,
        favorite: view.favorite,
        reprompt: view.reprompt,
        organization_use_totp: view.organization_use_totp,
        edit: view.edit,
        permissions: view.permissions,
        view_password: view.view_password,
        local_data,
        attachments,
        fields: None,
        password_history: None,
        creation_date: view.creation_date,
        deleted_date: view.deleted_date,
        revision_date: view.revision_date,
        archived_date: view.archived_date,
        data: Some(sealed_string),
    })
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::IdentifyKey;
    use uuid::Uuid;

    use super::*;
    use crate::cipher::{
        blob::conversions::test_support::{create_shell_cipher_view, create_test_key_store},
        card::CardView,
        cipher::{CipherId, CipherRepromptType, CipherType},
        identity::IdentityView,
        login::LoginView,
        secure_note::{SecureNoteType, SecureNoteView},
        ssh_key::SshKeyView,
    };

    fn make_test_cipher_with_data(
        ctx: &mut KeyStoreContext<KeyIds>,
        data: Option<String>,
    ) -> Cipher {
        let name = "test"
            .encrypt(ctx, bitwarden_core::key_management::SymmetricKeyId::User)
            .unwrap();
        Cipher {
            id: None,
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name,
            notes: None,
            r#type: CipherType::SecureNote,
            login: None,
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: false,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            fields: None,
            password_history: None,
            creation_date: chrono::Utc::now(),
            deleted_date: None,
            revision_date: chrono::Utc::now(),
            archived_date: None,
            data,
        }
    }

    #[test]
    fn test_is_blob_encrypted_true() {
        let (key_store, _) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let mut view = create_shell_cipher_view(CipherType::SecureNote);
        view.name = "Blob Test".to_string();
        view.secure_note = Some(SecureNoteView {
            r#type: SecureNoteType::Generic,
        });

        let cipher = create_blob_cipher(&mut view, &mut ctx).unwrap();
        assert!(is_blob_encrypted(&cipher));
    }

    #[test]
    fn test_is_blob_encrypted_false_no_data() {
        let (key_store, _) = create_test_key_store();
        let mut ctx = key_store.context_mut();
        let cipher = make_test_cipher_with_data(&mut ctx, None);
        assert!(!is_blob_encrypted(&cipher));
    }

    #[test]
    fn test_is_blob_encrypted_false_invalid_data() {
        let (key_store, _) = create_test_key_store();
        let mut ctx = key_store.context_mut();
        let cipher = make_test_cipher_with_data(&mut ctx, Some("not a valid blob".to_string()));
        assert!(!is_blob_encrypted(&cipher));
    }

    #[test]
    fn test_seal_unseal_round_trip() {
        let (key_store, _) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let mut view = create_shell_cipher_view(CipherType::SecureNote);
        view.name = "Round Trip".to_string();
        view.notes = Some("Some notes".to_string());
        view.secure_note = Some(SecureNoteView {
            r#type: SecureNoteType::Generic,
        });
        view.generate_cipher_key(&mut ctx, view.key_identifier())
            .unwrap();

        let sealed_string = seal_cipher(&view, &mut ctx).unwrap();

        let mut cipher = make_test_cipher_with_data(&mut ctx, Some(sealed_string));
        cipher.key = view.key.clone();

        let blob = unseal_cipher(&cipher, &mut ctx).unwrap();
        assert_eq!(blob.name, "Round Trip");
        assert_eq!(blob.notes, Some("Some notes".to_string()));
    }

    #[test]
    fn test_create_blob_cipher_sets_data() {
        let (key_store, _) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let mut view = create_shell_cipher_view(CipherType::SecureNote);
        view.name = "Has Data".to_string();
        view.secure_note = Some(SecureNoteView {
            r#type: SecureNoteType::Generic,
        });

        let cipher = create_blob_cipher(&mut view, &mut ctx).unwrap();
        assert!(cipher.data.is_some());
    }

    #[test]
    fn test_create_blob_cipher_clears_legacy_fields() {
        let (key_store, _) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let mut view = create_shell_cipher_view(CipherType::Login);
        view.name = "Login".to_string();
        view.login = Some(LoginView {
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            password_revision_date: None,
            uris: None,
            totp: None,
            autofill_on_page_load: None,
            fido2_credentials: None,
        });

        let cipher = create_blob_cipher(&mut view, &mut ctx).unwrap();
        assert!(cipher.login.is_none());
        assert!(cipher.card.is_none());
        assert!(cipher.identity.is_none());
        assert!(cipher.secure_note.is_none());
        assert!(cipher.ssh_key.is_none());
        assert!(cipher.notes.is_none());
        assert!(cipher.fields.is_none());
        assert!(cipher.password_history.is_none());
    }

    #[test]
    fn test_create_blob_cipher_generates_key() {
        let (key_store, _) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let mut view = create_shell_cipher_view(CipherType::SecureNote);
        view.secure_note = Some(SecureNoteView {
            r#type: SecureNoteType::Generic,
        });
        assert!(view.key.is_none());

        let cipher = create_blob_cipher(&mut view, &mut ctx).unwrap();
        assert!(cipher.key.is_some());
        assert!(view.key.is_some());
    }

    #[test]
    fn test_create_blob_cipher_preserves_metadata() {
        let (key_store, _) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let cipher_id = CipherId::new(Uuid::new_v4());
        let mut view = create_shell_cipher_view(CipherType::SecureNote);
        view.id = Some(cipher_id);
        view.favorite = true;
        view.reprompt = CipherRepromptType::Password;
        view.name = "Metadata Test".to_string();
        view.secure_note = Some(SecureNoteView {
            r#type: SecureNoteType::Generic,
        });

        let cipher = create_blob_cipher(&mut view, &mut ctx).unwrap();
        assert_eq!(cipher.id, Some(cipher_id));
        assert!(cipher.favorite);
        assert_eq!(cipher.reprompt, CipherRepromptType::Password);
        assert_eq!(cipher.r#type, CipherType::SecureNote);
        assert_eq!(cipher.creation_date, view.creation_date);
        assert_eq!(cipher.revision_date, view.revision_date);
    }

    #[test]
    fn test_create_blob_cipher_each_type() {
        let (key_store, _) = create_test_key_store();

        // Login
        {
            let mut ctx = key_store.context_mut();
            let mut view = create_shell_cipher_view(CipherType::Login);
            view.name = "Login".to_string();
            view.login = Some(LoginView {
                username: Some("user".to_string()),
                password: None,
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            });
            assert!(create_blob_cipher(&mut view, &mut ctx).is_ok());
        }

        // Card
        {
            let mut ctx = key_store.context_mut();
            let mut view = create_shell_cipher_view(CipherType::Card);
            view.name = "Card".to_string();
            view.card = Some(CardView {
                cardholder_name: Some("John".to_string()),
                exp_month: None,
                exp_year: None,
                code: None,
                brand: None,
                number: None,
            });
            assert!(create_blob_cipher(&mut view, &mut ctx).is_ok());
        }

        // Identity
        {
            let mut ctx = key_store.context_mut();
            let mut view = create_shell_cipher_view(CipherType::Identity);
            view.name = "Identity".to_string();
            view.identity = Some(IdentityView {
                title: None,
                first_name: Some("Jane".to_string()),
                middle_name: None,
                last_name: None,
                address1: None,
                address2: None,
                address3: None,
                city: None,
                state: None,
                postal_code: None,
                country: None,
                company: None,
                email: None,
                phone: None,
                ssn: None,
                username: None,
                passport_number: None,
                license_number: None,
            });
            assert!(create_blob_cipher(&mut view, &mut ctx).is_ok());
        }

        // SecureNote
        {
            let mut ctx = key_store.context_mut();
            let mut view = create_shell_cipher_view(CipherType::SecureNote);
            view.name = "Note".to_string();
            view.secure_note = Some(SecureNoteView {
                r#type: SecureNoteType::Generic,
            });
            assert!(create_blob_cipher(&mut view, &mut ctx).is_ok());
        }

        // SshKey
        {
            let mut ctx = key_store.context_mut();
            let mut view = create_shell_cipher_view(CipherType::SshKey);
            view.name = "SSH".to_string();
            view.ssh_key = Some(SshKeyView {
                private_key: "private".to_string(),
                public_key: "public".to_string(),
                fingerprint: "fingerprint".to_string(),
            });
            assert!(create_blob_cipher(&mut view, &mut ctx).is_ok());
        }
    }

    #[test]
    fn test_end_to_end_round_trip() {
        let (key_store, _) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let mut view = create_shell_cipher_view(CipherType::Login);
        view.name = "My Login".to_string();
        view.notes = Some("Secret notes".to_string());
        view.login = Some(LoginView {
            username: Some("testuser@example.com".to_string()),
            password: Some("p@ssw0rd".to_string()),
            password_revision_date: None,
            uris: None,
            totp: None,
            autofill_on_page_load: None,
            fido2_credentials: None,
        });

        let cipher = create_blob_cipher(&mut view, &mut ctx).unwrap();
        assert!(is_blob_encrypted(&cipher));
        assert!(!is_legacy_cipher(&cipher));

        let blob = unseal_cipher(&cipher, &mut ctx).unwrap();

        let mut restored = create_shell_cipher_view(CipherType::Login);
        let cipher_key =
            Cipher::decrypt_cipher_key(&mut ctx, cipher.key_identifier(), &cipher.key).unwrap();
        blob.apply_to_cipher_view(&mut restored, &mut ctx, cipher_key)
            .unwrap();

        assert_eq!(restored.name, "My Login");
        assert_eq!(restored.notes, Some("Secret notes".to_string()));
        let login = restored.login.unwrap();
        assert_eq!(login.username, Some("testuser@example.com".to_string()));
        assert_eq!(login.password, Some("p@ssw0rd".to_string()));
    }
}
