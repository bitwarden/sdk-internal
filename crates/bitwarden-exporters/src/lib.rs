#![doc = include_str!("../README.md")]

use std::fmt;

use bitwarden_vault::{
    CipherRepromptType, CipherView, Fido2CredentialFullView, LoginUriView, UriMatchType,
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

impl From<ImportingCipher> for CipherView {
    fn from(value: ImportingCipher) -> Self {
        let login = match value.r#type {
            CipherType::Login(login) => {
                let l: Vec<LoginUriView> = login
                    .login_uris
                    .into_iter()
                    .map(LoginUriView::from)
                    .collect();

                Some(bitwarden_vault::LoginView {
                    username: login.username,
                    password: login.password,
                    password_revision_date: None,
                    uris: if l.is_empty() { None } else { Some(l) },
                    totp: login.totp,
                    autofill_on_page_load: None,
                    fido2_credentials: None,
                })
            }
            _ => None,
        };

        Self {
            id: None,
            organization_id: None,
            folder_id: value.folder_id,
            collection_ids: vec![],
            key: None,
            name: value.name,
            notes: None,
            r#type: bitwarden_vault::CipherType::Login,
            login,
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            favorite: value.favorite,
            reprompt: CipherRepromptType::None,
            organization_use_totp: true,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            fields: None,
            password_history: None,
            creation_date: value.creation_date,
            deleted_date: None,
            revision_date: value.revision_date,
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
#[derive(Clone, Debug, PartialEq)]
pub struct Field {
    pub name: Option<String>,
    pub value: Option<String>,
    pub r#type: u8,
    pub linked_id: Option<u32>,
}

#[allow(missing_docs)]
#[derive(Clone)]
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
pub struct Login {
    pub username: Option<String>,
    pub password: Option<String>,
    pub login_uris: Vec<LoginUri>,
    pub totp: Option<String>,

    pub fido2_credentials: Option<Vec<Fido2Credential>>,
}

#[allow(missing_docs)]
#[derive(Clone, Debug, PartialEq)]
pub struct LoginUri {
    pub uri: Option<String>,
    pub r#match: Option<u8>,
}

#[allow(missing_docs)]
#[derive(Clone)]
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
pub struct SecureNote {
    pub r#type: SecureNoteType,
}

#[allow(missing_docs)]
#[derive(Clone)]
pub enum SecureNoteType {
    Generic = 0,
}

#[allow(missing_docs)]
#[derive(Clone, Default, Debug, PartialEq)]
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
pub struct SshKey {
    /// [OpenSSH private key](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key), in PEM encoding.
    pub private_key: String,
    /// Ssh public key (ed25519/rsa) according to [RFC4253](https://datatracker.ietf.org/doc/html/rfc4253#section-6.6)
    pub public_key: String,
    /// SSH fingerprint using SHA256 in the format: `SHA256:BASE64_ENCODED_FINGERPRINT`
    pub fingerprint: String,
}
