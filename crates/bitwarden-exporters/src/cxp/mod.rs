use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bitwarden_core::MissingFieldError;
use bitwarden_crypto::generate_random_bytes;
use bitwarden_fido::{string_to_guid_bytes, InvalidGuid};
use chrono::{DateTime, Utc};
use credential_exchange_types::{
    format::{
        Account as CxpAccount, BasicAuthCredential, Credential, EditableField, FieldType, Item,
        ItemType, PasskeyCredential,
    },
    B64Url,
};
use thiserror::Error;
use uuid::Uuid;

use crate::{Cipher, CipherType, Fido2Credential, ImportingCipher, Login, LoginUri};

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

    let account = CxpAccount {
        id: account.id.as_bytes().as_slice().into(),
        user_name: "".to_owned(),
        email: account.email,
        full_name: account.name,
        icon: None,
        collections: vec![],
        items,
        extensions: None,
    };

    Ok(serde_json::to_string(&account)?)
}

pub(crate) fn parse_cxf(payload: String) -> Result<Vec<ImportingCipher>, CxpError> {
    let account: CxpAccount = serde_json::from_str(&payload)?;

    let items: Vec<ImportingCipher> = account.items.into_iter().flat_map(parse_item).collect();

    Ok(items)
}

fn group_credentials_by_type(credentials: Vec<Credential>) -> GroupedCredentials {
    GroupedCredentials {
        basic_auth: credentials
            .iter()
            .filter_map(|c| match c {
                Credential::BasicAuth(basic_auth) => Some(basic_auth.clone()),
                _ => None,
            })
            .collect(),
        passkey: credentials
            .iter()
            .filter_map(|c| match c {
                Credential::Passkey(passkey) => Some(passkey.clone()),
                _ => None,
            })
            .collect(),
    }
}

struct GroupedCredentials {
    basic_auth: Vec<BasicAuthCredential>,
    passkey: Vec<PasskeyCredential>,
}

fn parse_item(value: Item) -> Vec<ImportingCipher> {
    let grouped = group_credentials_by_type(value.credentials);

    match value.ty {
        ItemType::Login => {
            let basic_auth = grouped.basic_auth.first();
            let passkey = grouped.passkey.first();

            let login = Login {
                username: basic_auth.and_then(|v| v.username.as_ref().map(|u| u.value.clone())),
                password: basic_auth.and_then(|v| v.password.as_ref().map(|u| u.value.clone())),
                login_uris: basic_auth
                    .map(|v| {
                        v.urls
                            .iter()
                            .map(|u| LoginUri {
                                uri: Some(u.clone()),
                                r#match: None,
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                totp: None,
                fido2_credentials: passkey.map(|p| {
                    vec![Fido2Credential {
                        credential_id: format!("b64.{}", p.credential_id),
                        key_type: "public-key".to_string(),
                        key_algorithm: "ECDSA".to_string(),
                        key_curve: "P-256".to_string(),
                        key_value: URL_SAFE_NO_PAD.encode(&p.key),
                        rp_id: p.rp_id.clone(),
                        user_handle: Some(p.user_handle.to_string()),
                        user_name: Some(p.user_name.clone()),
                        counter: 0,
                        rp_name: Some(p.rp_id.clone()),
                        user_display_name: Some(p.user_display_name.clone()),
                        discoverable: "true".to_string(),
                        creation_date: DateTime::from_timestamp(value.creation_at as i64, 0)
                            .unwrap_or(Utc::now()),
                    }]
                }),
            };

            vec![ImportingCipher {
                folder_id: None, // TODO: Handle folders
                name: value.title,
                notes: None,
                r#type: CipherType::Login(Box::new(login)),
                favorite: false,
                reprompt: 0,
                fields: vec![],
                revision_date: DateTime::from_timestamp(value.modified_at as i64, 0)
                    .unwrap_or(Utc::now()),
                creation_date: DateTime::from_timestamp(value.creation_at as i64, 0)
                    .unwrap_or(Utc::now()),
                deleted_date: None,
            }]
        }
        _ => vec![],
    }
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
            favorite: Some(value.favorite),
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
        let mut credentials = vec![];

        credentials.push(Credential::BasicAuth(login.clone().into()));

        if let Some(fido2_credentials) = login.fido2_credentials {
            for fido2_credential in fido2_credentials {
                let c = fido2_credential.try_into();
                if let Ok(c) = c {
                    credentials.push(Credential::Passkey(c))
                }
            }
        }

        credentials
    }
}

impl From<Login> for BasicAuthCredential {
    fn from(login: Login) -> Self {
        BasicAuthCredential {
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
        }
    }
}

#[derive(Error, Debug)]
pub enum PasskeyError {
    #[error("Counter is not zero")]
    CounterNotZero,
    #[error(transparent)]
    InvalidGuid(InvalidGuid),
    #[error(transparent)]
    MissingField(MissingFieldError),
    #[error(transparent)]
    InvalidBase64(#[from] base64::DecodeError),
}

impl TryFrom<Fido2Credential> for PasskeyCredential {
    type Error = PasskeyError;

    fn try_from(value: Fido2Credential) -> Result<Self, Self::Error> {
        if value.counter > 0 {
            return Err(PasskeyError::CounterNotZero);
        }

        Ok(PasskeyCredential {
            credential_id: string_to_guid_bytes(&value.credential_id)
                .map_err(PasskeyError::InvalidGuid)?
                .into(),
            rp_id: value.rp_id,
            user_name: value.user_name.unwrap_or("".to_string()),
            user_display_name: value.user_display_name.unwrap_or("".to_string()),
            user_handle: value
                .user_handle
                .map(|v| URL_SAFE_NO_PAD.decode(v))
                .transpose()?
                .map(|v| v.into())
                .ok_or(PasskeyError::MissingField(MissingFieldError("user_handle")))?,
            key: URL_SAFE_NO_PAD.decode(value.key_value)?.into(),
            fido2_extensions: None,
        })
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
    use base64::prelude::BASE64_STANDARD_NO_PAD;
    use chrono::{DateTime, Utc};
    use credential_exchange_types::protocol::CredentialType;

    use super::*;
    use crate::{CipherType, Fido2Credential, Field, Login, LoginUri};

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
                fido2_credentials: Some(vec![Fido2Credential {
                    credential_id: "e8d88789-e916-e196-3cbd-81dafae71bbc".to_string(),
                    key_type: "public-key".to_string(),
                    key_algorithm: "ECDSA".to_string(),
                    key_curve: "P-256".to_string(),
                    key_value: URL_SAFE_NO_PAD.encode([0, 1, 2, 3, 4, 5, 6]),
                    rp_id: "123".to_string(),
                    user_handle: Some(URL_SAFE_NO_PAD.encode([0, 1, 2, 3, 4, 5, 6])),
                    user_name: None,
                    counter: 0,
                    rp_name: None,
                    user_display_name: None,
                    discoverable: "true".to_string(),
                    creation_date: "2024-06-07T14:12:36.150Z".parse().unwrap(),
                }]),
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
        assert_eq!(item.ty, ItemType::Login);
        assert_eq!(item.title, "Bitwarden");
        assert_eq!(item.subtitle, None);
        assert_eq!(item.credentials.len(), 2);
        assert_eq!(item.tags, None);
        assert!(item.extensions.is_none());

        let credential = &item.credentials[0];

        match credential {
            Credential::BasicAuth(basic_auth) => {
                let username = basic_auth.username.as_ref().unwrap();
                assert_eq!(username.field_type, FieldType::String);
                assert_eq!(username.value, "test@bitwarden.com");
                assert!(username.label.is_none());

                let password = basic_auth.password.as_ref().unwrap();
                assert_eq!(password.field_type, FieldType::ConcealedString);
                assert_eq!(password.value, "asdfasdfasdf");
                assert!(password.label.is_none());

                assert_eq!(
                    basic_auth.urls,
                    vec!["https://vault.bitwarden.com".to_string()]
                );
            }
            _ => panic!("Expected Credential::BasicAuth"),
        }

        let credential = &item.credentials[1];

        match credential {
            Credential::Passkey(passkey) => {
                assert_eq!(passkey.credential_id.to_string(), "6NiHiekW4ZY8vYHa-ucbvA");
            }
            _ => panic!("Expected Credential::Passkey"),
        }
    }

    #[test]
    fn test_parse_item() {
        let item = Item {
            id: [0, 1, 2, 3, 4, 5, 6].as_ref().into(),
            creation_at: 1706613834,
            modified_at: 1706623773,
            ty: ItemType::Login,
            title: "Bitwarden".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![],
            tags: None,
            extensions: None,
        };

        let _ciphers: Vec<ImportingCipher> = parse_item(item);
    }

    #[test]
    fn test_parse_passkey() {
        let item = Item {
            id: URL_SAFE_NO_PAD
                .decode("Njk1RERENTItNkQ0Ny00NERBLTlFN0EtNDM1MjNEQjYzNjVF")
                .unwrap()
                .as_slice()
                .into(),
            creation_at: 1732181986,
            modified_at: 1732182026,
            ty: ItemType::Login,
            title: "opotonniee.github.io".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![Credential::Passkey(PasskeyCredential {
                credential_id: URL_SAFE_NO_PAD
                    .decode("6NiHiekW4ZY8vYHa-ucbvA")
                    .unwrap()
                    .as_slice()
                    .into(),
                rp_id: "opotonniee.github.io".to_string(),
                user_name: "alex muller".to_string(),
                user_display_name: "alex muller".to_string(),
                user_handle: URL_SAFE_NO_PAD
                    .decode("YWxleCBtdWxsZXI")
                    .unwrap()
                    .as_slice()
                    .into(),
                key: URL_SAFE_NO_PAD
                    .decode("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPzvtWYWmIsvqqr3LsZB0K-cbjuhJSGTGziL1LksHAPShRANCAAT-vqHTyEDS9QBNNi2BNLyu6TunubJT_L3G3i7KLpEDhMD15hi24IjGBH0QylJIrvlT4JN2tdRGF436XGc-VoAl")
                    .unwrap()
                    .as_slice()
                    .into(),
                fido2_extensions: None,
            })],
            tags: None,
            extensions: None,
        };

        let _ciphers: Vec<ImportingCipher> = parse_item(item);

        /*
        {
            "id": "Njk1RERENTItNkQ0Ny00NERBLTlFN0EtNDM1MjNEQjYzNjVF",
            "title": "opotonniee.github.io",
            "modifiedAt": 1732182026,
            "type": "login",
            "credentials": [
              {
                "key": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPzvtWYWmIsvqqr3LsZB0K-cbjuhJSGTGziL1LksHAPShRANCAAT-vqHTyEDS9QBNNi2BNLyu6TunubJT_L3G3i7KLpEDhMD15hi24IjGBH0QylJIrvlT4JN2tdRGF436XGc-VoAl",
                "userName": "alex muller",
                "userHandle": "YWxleCBtdWxsZXI",
                "credentialID": "6NiHiekW4ZY8vYHa-ucbvA",
                "userDisplayName": "alex muller",
                "rpID": "opotonniee.github.io",
                "type": "passkey"
              }
            ],
            "creationAt": 1732181986
          },
           */
    }
}
