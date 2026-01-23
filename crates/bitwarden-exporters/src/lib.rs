#![doc = include_str!("../README.md")]

use std::fmt;

use bitwarden_vault::{
    CipherRepromptType, CipherView, Fido2CredentialFullView, FieldView, FolderId, LoginUriView,
    UriMatchType,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod csv;
mod cxf;
pub use cxf::Account;
mod encrypted_json;
mod exporter_client;
mod json;
mod models;
pub use exporter_client::{ExporterClient, ExporterClientExt};
mod error;
mod export;
pub use error::ExportError;

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub enum ExportFormat {
    Csv,
    Json,
    EncryptedJson { password: String },
}

/// Export representation of a Bitwarden folder.
///
/// These are mostly duplicated from the `bitwarden` vault models to facilitate a stable export API
/// that is not tied to the internal vault models. We may revisit this in the future.
#[allow(missing_docs)]
pub struct Folder {
    pub id: Uuid,
    pub name: String,
}

/// Export representation of a Bitwarden cipher.
///
/// These are mostly duplicated from the `bitwarden` vault models to facilitate a stable export API
/// that is not tied to the internal vault models. We may revisit this in the future.
#[allow(missing_docs)]
#[derive(Clone)]
pub struct Cipher {
    pub id: Uuid,
    pub folder_id: Option<Uuid>,

    pub name: String,
    pub notes: Option<String>,

    pub r#type: CipherType,

    pub favorite: bool,
    pub reprompt: u8,

    pub fields: Vec<Field>,

    pub revision_date: DateTime<Utc>,
    pub creation_date: DateTime<Utc>,
    pub deleted_date: Option<DateTime<Utc>>,
}

/// Import representation of a Bitwarden cipher.
///
/// These are mostly duplicated from the `bitwarden` vault models to facilitate a stable export API
/// that is not tied to the internal vault models. We may revisit this in the future.
#[allow(missing_docs)]
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct ImportingCipher {
    pub folder_id: Option<Uuid>,

    pub name: String,
    pub notes: Option<String>,

    pub r#type: CipherType,

    pub favorite: bool,
    pub reprompt: u8,

    pub fields: Vec<Field>,

    pub revision_date: DateTime<Utc>,
    pub creation_date: DateTime<Utc>,
    pub deleted_date: Option<DateTime<Utc>>,
}

impl From<Login> for bitwarden_vault::LoginView {
    fn from(login: Login) -> Self {
        let l: Vec<LoginUriView> = login
            .login_uris
            .into_iter()
            .map(LoginUriView::from)
            .collect();

        bitwarden_vault::LoginView {
            username: login.username,
            password: login.password,
            password_revision_date: None,
            uris: if l.is_empty() { None } else { Some(l) },
            totp: login.totp,
            autofill_on_page_load: None,
            // Fido2Credentials are set by `encrypt_import`.
            fido2_credentials: None,
        }
    }
}

impl From<SecureNote> for bitwarden_vault::SecureNoteView {
    fn from(secure_note: SecureNote) -> Self {
        bitwarden_vault::SecureNoteView {
            r#type: secure_note.r#type.into(),
        }
    }
}

impl From<Card> for bitwarden_vault::CardView {
    fn from(card: Card) -> Self {
        bitwarden_vault::CardView {
            cardholder_name: card.cardholder_name,
            brand: card.brand,
            number: card.number,
            exp_month: card.exp_month,
            exp_year: card.exp_year,
            code: card.code,
        }
    }
}

impl From<Identity> for bitwarden_vault::IdentityView {
    fn from(identity: Identity) -> Self {
        bitwarden_vault::IdentityView {
            title: identity.title,
            first_name: identity.first_name,
            middle_name: identity.middle_name,
            last_name: identity.last_name,
            address1: identity.address1,
            address2: identity.address2,
            address3: identity.address3,
            city: identity.city,
            state: identity.state,
            postal_code: identity.postal_code,
            country: identity.country,
            company: identity.company,
            email: identity.email,
            phone: identity.phone,
            ssn: identity.ssn,
            username: identity.username,
            passport_number: identity.passport_number,
            license_number: identity.license_number,
        }
    }
}

impl From<SshKey> for bitwarden_vault::SshKeyView {
    fn from(ssh_key: SshKey) -> Self {
        bitwarden_vault::SshKeyView {
            private_key: ssh_key.private_key,
            public_key: ssh_key.public_key,
            fingerprint: ssh_key.fingerprint,
        }
    }
}

impl From<ImportingCipher> for CipherView {
    fn from(value: ImportingCipher) -> Self {
        let (cipher_type, login, identity, card, secure_note, ssh_key) = match value.r#type {
            CipherType::Login(login) => (
                bitwarden_vault::CipherType::Login,
                Some((*login).into()),
                None,
                None,
                None,
                None,
            ),
            CipherType::SecureNote(secure_note) => (
                bitwarden_vault::CipherType::SecureNote,
                None,
                None,
                None,
                Some((*secure_note).into()),
                None,
            ),
            CipherType::Card(card) => (
                bitwarden_vault::CipherType::Card,
                None,
                None,
                Some((*card).into()),
                None,
                None,
            ),
            CipherType::Identity(identity) => (
                bitwarden_vault::CipherType::Identity,
                None,
                Some((*identity).into()),
                None,
                None,
                None,
            ),
            CipherType::SshKey(ssh_key) => (
                bitwarden_vault::CipherType::SshKey,
                None,
                None,
                None,
                None,
                Some((*ssh_key).into()),
            ),
        };

        Self {
            id: None,
            organization_id: None,
            folder_id: value.folder_id.map(FolderId::new),
            collection_ids: vec![],
            key: None,
            name: value.name,
            notes: value.notes,
            r#type: cipher_type,
            login,
            identity,
            card,
            secure_note,
            ssh_key,
            favorite: value.favorite,
            reprompt: CipherRepromptType::None,
            organization_use_totp: true,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            attachment_decryption_failures: None,
            fields: {
                let fields: Vec<FieldView> = value.fields.into_iter().map(Into::into).collect();
                if fields.is_empty() {
                    None
                } else {
                    Some(fields)
                }
            },
            password_history: None,
            creation_date: value.creation_date,
            deleted_date: None,
            revision_date: value.revision_date,
            archived_date: None,
        }
    }
}

impl From<LoginUri> for bitwarden_vault::LoginUriView {
    fn from(value: LoginUri) -> Self {
        Self {
            uri: value.uri,
            r#match: value.r#match.and_then(|m| match m {
                0 => Some(UriMatchType::Domain),
                1 => Some(UriMatchType::Host),
                2 => Some(UriMatchType::StartsWith),
                3 => Some(UriMatchType::Exact),
                4 => Some(UriMatchType::RegularExpression),
                5 => Some(UriMatchType::Never),
                _ => None,
            }),
            uri_checksum: None,
        }
    }
}

#[allow(missing_docs)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub name: Option<String>,
    pub value: Option<String>,
    pub r#type: u8,
    pub linked_id: Option<u32>,
}

#[allow(missing_docs)]
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum CipherType {
    Login(Box<Login>),
    SecureNote(Box<SecureNote>),
    Card(Box<Card>),
    Identity(Box<Identity>),
    SshKey(Box<SshKey>),
}

impl fmt::Display for CipherType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CipherType::Login(_) => write!(f, "login"),
            CipherType::SecureNote(_) => write!(f, "note"),
            CipherType::Card(_) => write!(f, "card"),
            CipherType::Identity(_) => write!(f, "identity"),
            CipherType::SshKey(_) => write!(f, "ssh_key"),
        }
    }
}

#[allow(missing_docs)]
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Login {
    pub username: Option<String>,
    pub password: Option<String>,
    pub login_uris: Vec<LoginUri>,
    pub totp: Option<String>,

    pub fido2_credentials: Option<Vec<Fido2Credential>>,
}

#[allow(missing_docs)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginUri {
    pub uri: Option<String>,
    pub r#match: Option<u8>,
}

#[allow(missing_docs)]
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Fido2Credential {
    pub credential_id: String,
    pub key_type: String,
    pub key_algorithm: String,
    pub key_curve: String,
    pub key_value: String,
    pub rp_id: String,
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub counter: u32,
    pub rp_name: Option<String>,
    pub user_display_name: Option<String>,
    pub discoverable: String,
    pub creation_date: DateTime<Utc>,
}

impl From<Fido2Credential> for Fido2CredentialFullView {
    fn from(value: Fido2Credential) -> Self {
        Fido2CredentialFullView {
            credential_id: value.credential_id,
            key_type: value.key_type,
            key_algorithm: value.key_algorithm,
            key_curve: value.key_curve,
            key_value: value.key_value,
            rp_id: value.rp_id,
            user_handle: value.user_handle,
            user_name: value.user_name,
            counter: value.counter.to_string(),
            rp_name: value.rp_name,
            user_display_name: value.user_display_name,
            discoverable: value.discoverable,
            creation_date: value.creation_date,
        }
    }
}

#[allow(missing_docs)]
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Card {
    pub cardholder_name: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
}

#[allow(missing_docs)]
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct SecureNote {
    pub r#type: SecureNoteType,
}

#[allow(missing_docs)]
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum SecureNoteType {
    Generic = 0,
}

#[allow(missing_docs)]
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Identity {
    pub title: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub address3: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub company: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub ssn: Option<String>,
    pub username: Option<String>,
    pub passport_number: Option<String>,
    pub license_number: Option<String>,
}

#[allow(missing_docs)]
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct SshKey {
    /// [OpenSSH private key](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key), in PEM encoding.
    pub private_key: String,
    /// Ssh public key (ed25519/rsa) according to [RFC4253](https://datatracker.ietf.org/doc/html/rfc4253#section-6.6)
    pub public_key: String,
    /// SSH fingerprint using SHA256 in the format: `SHA256:BASE64_ENCODED_FINGERPRINT`
    pub fingerprint: String,
}

#[cfg(test)]
mod tests {
    use bitwarden_vault::{CipherType as VaultCipherType, FieldType};
    use chrono::{DateTime, Utc};

    use super::*;

    #[test]
    fn test_importing_cipher_to_cipher_view_login() {
        let test_date: DateTime<Utc> = "2024-01-30T17:55:36.150Z".parse().unwrap();
        let test_folder_id = uuid::Uuid::new_v4();

        let importing_cipher = ImportingCipher {
            folder_id: Some(test_folder_id),
            name: "Test Login".to_string(),
            notes: Some("Test notes".to_string()),
            r#type: CipherType::Login(Box::new(Login {
                username: Some("test@example.com".to_string()),
                password: Some("password123".to_string()),
                login_uris: vec![LoginUri {
                    uri: Some("https://example.com".to_string()),
                    r#match: Some(0), // Domain match
                }],
                totp: Some("otpauth://totp/test".to_string()),
                fido2_credentials: None,
            })),
            favorite: true,
            reprompt: 1,
            fields: vec![Field {
                name: Some("CustomField".to_string()),
                value: Some("CustomValue".to_string()),
                r#type: 0,
                linked_id: None,
            }],
            revision_date: test_date,
            creation_date: test_date,
            deleted_date: None,
        };

        let cipher_view: CipherView = importing_cipher.into();

        assert_eq!(cipher_view.id, None);
        assert_eq!(cipher_view.organization_id, None);
        assert_eq!(
            cipher_view.folder_id.unwrap().to_string(),
            test_folder_id.to_string()
        );
        assert_eq!(cipher_view.name, "Test Login");
        assert_eq!(cipher_view.notes.unwrap(), "Test notes");
        assert_eq!(cipher_view.r#type, VaultCipherType::Login);
        assert!(cipher_view.favorite);
        assert_eq!(cipher_view.creation_date, test_date);
        assert_eq!(cipher_view.revision_date, test_date);

        let fields = cipher_view.fields.unwrap();
        assert_eq!(fields.len(), 1);

        let field = fields.first().unwrap();
        assert_eq!(field.name, Some("CustomField".to_string()));
        assert_eq!(field.value, Some("CustomValue".to_string()));
        assert_eq!(field.r#type, FieldType::Text);
        assert_eq!(field.linked_id, None);

        let login = cipher_view.login.expect("Login should be present");
        assert_eq!(login.username, Some("test@example.com".to_string()));
        assert_eq!(login.password, Some("password123".to_string()));
        assert_eq!(login.totp, Some("otpauth://totp/test".to_string()));

        let uris = login.uris.expect("URIs should be present");
        assert_eq!(uris.len(), 1);
        assert_eq!(uris[0].uri, Some("https://example.com".to_string()));
        assert_eq!(uris[0].r#match, Some(bitwarden_vault::UriMatchType::Domain));
    }

    #[test]
    fn test_importing_cipher_to_cipher_view_secure_note() {
        let test_date: DateTime<Utc> = "2024-01-30T17:55:36.150Z".parse().unwrap();

        let importing_cipher = ImportingCipher {
            folder_id: None,
            name: "My Note".to_string(),
            notes: Some("This is a secure note".to_string()),
            r#type: CipherType::SecureNote(Box::new(SecureNote {
                r#type: SecureNoteType::Generic,
            })),
            favorite: false,
            reprompt: 0,
            fields: vec![],
            revision_date: test_date,
            creation_date: test_date,
            deleted_date: None,
        };

        let cipher_view: CipherView = importing_cipher.into();

        // Verify basic fields
        assert_eq!(cipher_view.id, None);
        assert_eq!(cipher_view.organization_id, None);
        assert_eq!(cipher_view.folder_id, None);
        assert_eq!(cipher_view.name, "My Note");
        assert_eq!(cipher_view.notes, Some("This is a secure note".to_string()));
        assert_eq!(cipher_view.r#type, bitwarden_vault::CipherType::SecureNote);
        assert!(!cipher_view.favorite);
        assert_eq!(cipher_view.creation_date, test_date);
        assert_eq!(cipher_view.revision_date, test_date);

        // For SecureNote type, secure_note should be populated and others should be None
        assert!(cipher_view.login.is_none());
        assert!(cipher_view.identity.is_none());
        assert!(cipher_view.card.is_none());
        assert!(cipher_view.secure_note.is_some());
        assert!(cipher_view.ssh_key.is_none());

        // Verify the secure note content
        let secure_note = cipher_view.secure_note.unwrap();
        assert!(matches!(
            secure_note.r#type,
            bitwarden_vault::SecureNoteType::Generic
        ));
    }

    #[test]
    fn test_importing_cipher_to_cipher_view_card() {
        let test_date: DateTime<Utc> = "2024-01-30T17:55:36.150Z".parse().unwrap();

        let importing_cipher = ImportingCipher {
            folder_id: None,
            name: "My Credit Card".to_string(),
            notes: Some("Credit card notes".to_string()),
            r#type: CipherType::Card(Box::new(Card {
                cardholder_name: Some("John Doe".to_string()),
                brand: Some("Visa".to_string()),
                number: Some("1234567812345678".to_string()),
                exp_month: Some("12".to_string()),
                exp_year: Some("2025".to_string()),
                code: Some("123".to_string()),
            })),
            favorite: false,
            reprompt: 0,
            fields: vec![],
            revision_date: test_date,
            creation_date: test_date,
            deleted_date: None,
        };

        let cipher_view: CipherView = importing_cipher.into();

        assert_eq!(cipher_view.r#type, bitwarden_vault::CipherType::Card);
        assert!(cipher_view.card.is_some());
        assert!(cipher_view.login.is_none());

        let card = cipher_view.card.unwrap();
        assert_eq!(card.cardholder_name, Some("John Doe".to_string()));
        assert_eq!(card.brand, Some("Visa".to_string()));
        assert_eq!(card.number, Some("1234567812345678".to_string()));
    }

    #[test]
    fn test_importing_cipher_to_cipher_view_identity() {
        let test_date: DateTime<Utc> = "2024-01-30T17:55:36.150Z".parse().unwrap();

        let importing_cipher = ImportingCipher {
            folder_id: None,
            name: "My Identity".to_string(),
            notes: None,
            r#type: CipherType::Identity(Box::new(Identity {
                title: Some("Dr.".to_string()),
                first_name: Some("Jane".to_string()),
                last_name: Some("Smith".to_string()),
                email: Some("jane@example.com".to_string()),
                ..Default::default()
            })),
            favorite: false,
            reprompt: 0,
            fields: vec![],
            revision_date: test_date,
            creation_date: test_date,
            deleted_date: None,
        };

        let cipher_view: CipherView = importing_cipher.into();

        assert_eq!(cipher_view.r#type, bitwarden_vault::CipherType::Identity);
        assert!(cipher_view.identity.is_some());
        assert!(cipher_view.login.is_none());

        let identity = cipher_view.identity.unwrap();
        assert_eq!(identity.title, Some("Dr.".to_string()));
        assert_eq!(identity.first_name, Some("Jane".to_string()));
        assert_eq!(identity.last_name, Some("Smith".to_string()));
        assert_eq!(identity.email, Some("jane@example.com".to_string()));
    }
}
