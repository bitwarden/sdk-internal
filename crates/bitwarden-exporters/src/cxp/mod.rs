use bitwarden_crypto::generate_random_bytes;
use chrono::Utc;
use credential_exchange_types::{
    format::{
        Account as CxpAccount, BasicAuthCredential, Credential, EditableField, FieldType, Header,
        Item, ItemType,
    },
    B64Url,
};
use uuid::Uuid;

use crate::{Cipher, CipherType, Login};

mod error;
pub use error::CxpError;

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Account {
    id: Uuid,
    email: String,
    name: Option<String>,
}

pub(crate) fn build_cxf(account: Account, ciphers: Vec<Cipher>) -> Result<String, CxpError> {
    let items: Vec<Item> = ciphers.into_iter().map(|cipher| cipher.into()).collect();

    let header = Header {
        version: 0,
        exporter: "Bitwarden".to_string(),
        timestamp: Utc::now().timestamp() as u64,
        accounts: vec![CxpAccount {
            id: account.id.as_bytes().as_slice().into(),
            user_name: "".to_owned(),
            email: account.email,
            full_name: account.name,
            icon: None,
            collections: vec![],
            items,
            extensions: None,
        }],
    };

    Ok(serde_json::to_string(&header)?)
}

impl From<Cipher> for Item {
    fn from(value: Cipher) -> Self {
        let credentials = value.r#type.clone().into();
        Self {
            id: value.id.as_bytes().as_slice().into(),
            creation_at: value.creation_date.timestamp() as u64,
            modified_at: value.revision_date.timestamp() as u64,
            ty: value.r#type.into(),
            title: value.name,
            subtitle: None,
            credentials,
            tags: None,
            extensions: None,
        }
    }
}

impl From<CipherType> for ItemType {
    // TODO: We should probably change this to try_from, so we can ignore types
    fn from(value: CipherType) -> Self {
        match value {
            CipherType::Login(_) => ItemType::Login,
            CipherType::Card(_) => ItemType::Login,
            CipherType::Identity(_) => ItemType::Identity,
            CipherType::SecureNote(_) => ItemType::Document,
            CipherType::SshKey(_) => todo!(),
        }
    }
}

impl From<Login> for Vec<Credential> {
    fn from(login: Login) -> Self {
        vec![Credential::BasicAuth(BasicAuthCredential {
            urls: login
                .login_uris
                .into_iter()
                .flat_map(|uri| uri.uri)
                .collect(),
            username: login.username.map(|value| EditableField {
                id: random_id(),
                field_type: FieldType::String,
                value,
                label: None,
            }),
            password: login.password.map(|value| EditableField {
                id: random_id(),
                field_type: FieldType::ConcealedString,
                value,
                label: None,
            }),
        })]
    }
}

impl From<CipherType> for Vec<Credential> {
    fn from(value: CipherType) -> Self {
        match value {
            CipherType::Login(login) => (*login).into(),
            CipherType::Card(_) => vec![],
            CipherType::Identity(_) => vec![],
            CipherType::SecureNote(_) => vec![],
            CipherType::SshKey(_) => vec![],
        }
    }
}

/// Generate a 32 byte random ID
fn random_id() -> B64Url {
    generate_random_bytes::<[u8; 32]>().as_slice().into()
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;
    use crate::{CipherType, Field, Login, LoginUri};

    #[test]
    fn test_login_to_item() {
        let cipher = Cipher {
            id: "25c8c414-b446-48e9-a1bd-b10700bbd740".parse().unwrap(),
            folder_id: Some("942e2984-1b9a-453b-b039-b107012713b9".parse().unwrap()),

            name: "Bitwarden".to_string(),
            notes: Some("My note".to_string()),

            r#type: CipherType::Login(Box::new(Login {
                username: Some("test@bitwarden.com".to_string()),
                password: Some("asdfasdfasdf".to_string()),
                login_uris: vec![LoginUri {
                    uri: Some("https://vault.bitwarden.com".to_string()),
                    r#match: None,
                }],
                totp: Some("ABC".to_string()),
            })),

            favorite: true,
            reprompt: 0,

            fields: vec![
                Field {
                    name: Some("Text".to_string()),
                    value: Some("A".to_string()),
                    r#type: 0,
                    linked_id: None,
                },
                Field {
                    name: Some("Hidden".to_string()),
                    value: Some("B".to_string()),
                    r#type: 1,
                    linked_id: None,
                },
                Field {
                    name: Some("Boolean (true)".to_string()),
                    value: Some("true".to_string()),
                    r#type: 2,
                    linked_id: None,
                },
                Field {
                    name: Some("Boolean (false)".to_string()),
                    value: Some("false".to_string()),
                    r#type: 2,
                    linked_id: None,
                },
                Field {
                    name: Some("Linked".to_string()),
                    value: None,
                    r#type: 3,
                    linked_id: Some(101),
                },
            ],

            revision_date: "2024-01-30T14:09:33.753Z".parse().unwrap(),
            creation_date: "2024-01-30T11:23:54.416Z".parse().unwrap(),
            deleted_date: None,
        };

        let item: Item = cipher.into();

        assert_eq!(
            item.creation_at,
            "2024-01-30T11:23:54.416Z"
                .parse::<DateTime<Utc>>()
                .unwrap()
                .timestamp() as u64
        );

        assert_eq!(item.id.to_string(), "JcjEFLRGSOmhvbEHALvXQA");
        assert_eq!(item.creation_at, 1706613834);
        assert_eq!(item.modified_at, 1706623773);
        assert!(matches!(item.ty, ItemType::Login));
        assert_eq!(item.title, "Bitwarden");
        assert_eq!(item.subtitle, None);
        assert_eq!(item.credentials.len(), 1);
        assert_eq!(item.tags, None);
        assert!(item.extensions.is_none());

        let credential = &item.credentials[0];

        match credential {
            Credential::BasicAuth(basic_auth) => {
                let username = basic_auth.username.as_ref().unwrap();
                assert!(matches!(username.field_type, FieldType::String));
                assert_eq!(username.value, "test@bitwarden.com");
                assert!(username.label.is_none());

                let password = basic_auth.password.as_ref().unwrap();
                assert!(matches!(password.field_type, FieldType::ConcealedString));
                assert_eq!(password.value, "asdfasdfasdf");
                assert!(password.label.is_none());

                assert_eq!(
                    basic_auth.urls,
                    vec!["https://vault.bitwarden.com".to_string()]
                );
            }
            _ => panic!("Expected Credential::BasicAuth"),
        }
    }
}
