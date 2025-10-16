use bitwarden_core::{MissingFieldError, key_management::KeyIds, require};
use bitwarden_crypto::KeyStore;
use bitwarden_vault::{
    CardView, Cipher, CipherType, CipherView, Fido2CredentialFullView, FieldType, FieldView,
    FolderView, IdentityView, LoginUriView, SecureNoteType, SecureNoteView, SshKeyView,
};

impl TryFrom<FolderView> for crate::Folder {
    type Error = MissingFieldError;

    fn try_from(value: FolderView) -> Result<Self, Self::Error> {
        Ok(Self {
            id: require!(value.id).into(),
            name: value.name,
        })
    }
}

impl crate::Cipher {
    pub(crate) fn from_cipher(
        key_store: &KeyStore<KeyIds>,
        cipher: Cipher,
    ) -> Result<Self, crate::error::ExportError> {
        let view: CipherView = key_store.decrypt(&cipher)?;

        let r = match view.r#type {
            CipherType::Login => crate::CipherType::Login(Box::new(from_login(&view, key_store)?)),
            CipherType::SecureNote => {
                let s = require!(view.secure_note);
                crate::CipherType::SecureNote(Box::new(s.into()))
            }
            CipherType::Card => {
                let c = require!(view.card);
                crate::CipherType::Card(Box::new(c.into()))
            }
            CipherType::Identity => {
                let i = require!(view.identity);
                crate::CipherType::Identity(Box::new(i.into()))
            }
            CipherType::SshKey => {
                let s = require!(view.ssh_key);
                crate::CipherType::SshKey(Box::new(s.into()))
            }
        };

        Ok(Self {
            id: require!(view.id).into(),
            folder_id: view.folder_id.map(|f| f.into()),
            name: view.name,
            notes: view.notes,
            r#type: r,
            favorite: view.favorite,
            reprompt: view.reprompt as u8,
            fields: view
                .fields
                .unwrap_or_default()
                .into_iter()
                .map(|f| f.into())
                .collect(),
            revision_date: view.revision_date,
            creation_date: view.creation_date,
            deleted_date: view.deleted_date,
        })
    }
}

/// Convert a `LoginView` into a `crate::Login`.
fn from_login(
    view: &CipherView,
    key_store: &KeyStore<KeyIds>,
) -> Result<crate::Login, MissingFieldError> {
    let l = require!(view.login.clone());

    Ok(crate::Login {
        username: l.username,
        password: l.password,
        login_uris: l
            .uris
            .unwrap_or_default()
            .into_iter()
            .map(|u| u.into())
            .collect(),
        totp: l.totp,
        fido2_credentials: l.fido2_credentials.as_ref().and_then(|_| {
            let credentials = view.get_fido2_credentials(&mut key_store.context()).ok()?;
            if credentials.is_empty() {
                None
            } else {
                Some(credentials.into_iter().map(|c| c.into()).collect())
            }
        }),
    })
}

impl From<LoginUriView> for crate::LoginUri {
    fn from(value: LoginUriView) -> Self {
        Self {
            r#match: value.r#match.map(|v| v as u8),
            uri: value.uri,
        }
    }
}

impl From<Fido2CredentialFullView> for crate::Fido2Credential {
    fn from(value: Fido2CredentialFullView) -> Self {
        Self {
            credential_id: value.credential_id,
            key_type: value.key_type,
            key_algorithm: value.key_algorithm,
            key_curve: value.key_curve,
            key_value: value.key_value,
            rp_id: value.rp_id,
            user_handle: value.user_handle,
            user_name: value.user_name,
            counter: value.counter.parse().expect("Invalid counter"),
            rp_name: value.rp_name,
            user_display_name: value.user_display_name,
            discoverable: value.discoverable,
            creation_date: value.creation_date,
        }
    }
}

impl From<SecureNoteView> for crate::SecureNote {
    fn from(view: SecureNoteView) -> Self {
        crate::SecureNote {
            r#type: view.r#type.into(),
        }
    }
}

impl From<CardView> for crate::Card {
    fn from(view: CardView) -> Self {
        crate::Card {
            cardholder_name: view.cardholder_name,
            exp_month: view.exp_month,
            exp_year: view.exp_year,
            code: view.code,
            brand: view.brand,
            number: view.number,
        }
    }
}

impl From<IdentityView> for crate::Identity {
    fn from(view: IdentityView) -> Self {
        crate::Identity {
            title: view.title,
            first_name: view.first_name,
            middle_name: view.middle_name,
            last_name: view.last_name,
            address1: view.address1,
            address2: view.address2,
            address3: view.address3,
            city: view.city,
            state: view.state,
            postal_code: view.postal_code,
            country: view.country,
            company: view.company,
            email: view.email,
            phone: view.phone,
            ssn: view.ssn,
            username: view.username,
            passport_number: view.passport_number,
            license_number: view.license_number,
        }
    }
}

impl From<SshKeyView> for crate::SshKey {
    fn from(view: SshKeyView) -> Self {
        crate::SshKey {
            private_key: view.private_key,
            public_key: view.public_key,
            fingerprint: view.fingerprint,
        }
    }
}

impl From<FieldView> for crate::Field {
    fn from(value: FieldView) -> Self {
        Self {
            name: value.name,
            value: value.value,
            r#type: value.r#type as u8,
            linked_id: value.linked_id.map(|id| id.into()),
        }
    }
}

impl From<crate::Field> for FieldView {
    fn from(value: crate::Field) -> Self {
        Self {
            name: value.name,
            value: value.value,
            r#type: value.r#type.try_into().unwrap_or(FieldType::Text),
            linked_id: value.linked_id.and_then(|id| id.try_into().ok()),
        }
    }
}

impl From<SecureNoteType> for crate::SecureNoteType {
    fn from(value: SecureNoteType) -> Self {
        match value {
            SecureNoteType::Generic => crate::SecureNoteType::Generic,
        }
    }
}

impl From<crate::SecureNoteType> for SecureNoteType {
    fn from(value: crate::SecureNoteType) -> Self {
        match value {
            crate::SecureNoteType::Generic => SecureNoteType::Generic,
        }
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::create_test_crypto_with_user_key;
    use bitwarden_crypto::SymmetricCryptoKey;
    use bitwarden_vault::{CipherId, CipherRepromptType, FolderId, LoginView};
    use chrono::{DateTime, Utc};

    use super::*;

    #[test]
    fn test_try_from_folder_view() {
        let test_id: uuid::Uuid = "fd411a1a-fec8-4070-985d-0e6560860e69".parse().unwrap();
        let view = FolderView {
            id: Some(FolderId::new(test_id)),
            name: "test_name".to_string(),
            revision_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
        };

        let f: crate::Folder = view.try_into().unwrap();

        assert_eq!(f.id, test_id);
        assert_eq!(f.name, "test_name".to_string());
    }

    #[test]
    fn test_from_login() {
        let key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let key_store = create_test_crypto_with_user_key(key);

        let test_id: uuid::Uuid = "fd411a1a-fec8-4070-985d-0e6560860e69".parse().unwrap();
        let view = CipherView {
            r#type: CipherType::Login,
            login: Some(LoginView {
                username: Some("test_username".to_string()),
                password: Some("test_password".to_string()),
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            id: Some(CipherId::new(test_id)),
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
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: true,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            fields: None,
            password_history: None,
            creation_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            archived_date: None,
        };

        let login = from_login(&view, &key_store).unwrap();

        assert_eq!(login.username, Some("test_username".to_string()));
        assert_eq!(login.password, Some("test_password".to_string()));
        assert!(login.login_uris.is_empty());
        assert_eq!(login.totp, None);
    }

    #[test]
    fn test_from_cipher_login() {
        let key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let key_store = create_test_crypto_with_user_key(key);

        let test_id: uuid::Uuid = "fd411a1a-fec8-4070-985d-0e6560860e69".parse().unwrap();
        let cipher_view = CipherView {
            r#type: CipherType::Login,
            login: Some(LoginView {
                username: Some("test_username".to_string()),
                password: Some("test_password".to_string()),
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            id: Some(CipherId::new(test_id)),
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
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: true,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            fields: None,
            password_history: None,
            creation_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            archived_date: None,
        };
        let encrypted = key_store.encrypt(cipher_view).unwrap();

        let cipher: crate::Cipher = crate::Cipher::from_cipher(&key_store, encrypted).unwrap();

        assert_eq!(cipher.id, test_id);
        assert_eq!(cipher.folder_id, None);
        assert_eq!(cipher.name, "My login".to_string());
        assert_eq!(cipher.notes, None);
        assert!(!cipher.favorite);
        assert_eq!(cipher.reprompt, 0);
        assert!(cipher.fields.is_empty());
        assert_eq!(
            cipher.revision_date,
            "2024-01-30T17:55:36.150Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(
            cipher.creation_date,
            "2024-01-30T17:55:36.150Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(cipher.deleted_date, None);

        if let crate::CipherType::Login(l) = cipher.r#type {
            assert_eq!(l.username, Some("test_username".to_string()));
            assert_eq!(l.password, Some("test_password".to_string()));
            assert!(l.login_uris.is_empty());
            assert_eq!(l.totp, None);
        } else {
            panic!("Expected login type");
        }
    }
}
