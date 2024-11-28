use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bitwarden_core::MissingFieldError;
use bitwarden_crypto::generate_random_bytes;
use bitwarden_fido::{string_to_guid_bytes, InvalidGuid};
use bitwarden_vault::{Totp, TotpAlgorithm};
use credential_exchange_types::{
    format::{
        Account as CxpAccount, BasicAuthCredential, Credential, EditableField, FieldType, Item,
        ItemType, OTPHashAlgorithm, PasskeyCredential,
    },
    B64Url,
};
use thiserror::Error;
use uuid::Uuid;

use crate::{cxp::CxpError, Cipher, CipherType, Fido2Credential, Login};

/// Temporary struct to hold metadata related to current account
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

impl From<Cipher> for Item {
    fn from(value: Cipher) -> Self {
        let mut credentials: Vec<Credential> = value.r#type.clone().into();

        if let Some(note) = value.notes {
            credentials.push(Credential::Note { content: note });
        }

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

impl From<Login> for Vec<Credential> {
    fn from(login: Login) -> Self {
        let mut credentials = vec![];

        if login.username.is_some() || login.password.is_some() || !login.login_uris.is_empty() {
            credentials.push(Credential::BasicAuth(login.clone().into()));
        }

        if let Some(totp) = login.totp {
            if let Ok(totp) = totp.parse::<Totp>() {
                // TODO(PM-15389): Properly set username/issuer.
                credentials.push(Credential::Totp {
                    secret: totp.secret.into(),
                    period: totp.period as u8,
                    digits: totp.digits as u8,
                    username: "".to_string(),
                    algorithm: match totp.algorithm {
                        TotpAlgorithm::Sha1 => OTPHashAlgorithm::Sha1,
                        TotpAlgorithm::Sha256 => OTPHashAlgorithm::Sha256,
                        TotpAlgorithm::Sha512 => OTPHashAlgorithm::Sha512,
                        TotpAlgorithm::Steam => OTPHashAlgorithm::Unknown("steam".to_string()),
                    },
                    issuer: None,
                })
            }
        }

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

/// Generate a 32 byte random ID
///
/// TODO: This should be removed shortly.
fn random_id() -> B64Url {
    generate_random_bytes::<[u8; 32]>().as_slice().into()
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

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;
    use crate::{Field, LoginUri};

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
                totp: Some("JBSWY3DPEHPK3PXP".to_string()),
                fido2_credentials: Some(vec![Fido2Credential {
                    credential_id: "e8d88789-e916-e196-3cbd-81dafae71bbc".to_string(),
                    key_type: "public-key".to_string(),
                    key_algorithm: "ECDSA".to_string(),
                    key_curve: "P-256".to_string(),
                    key_value: "AAECAwQFBg".to_string(),
                    rp_id: "123".to_string(),
                    user_handle: Some("AAECAwQFBg".to_string()),
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
        assert_eq!(item.tags, None);
        assert!(item.extensions.is_none());

        assert_eq!(item.credentials.len(), 4);

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
            Credential::Totp {
                secret,
                period,
                digits,
                username,
                algorithm,
                issuer,
            } => {
                assert_eq!(String::from(secret.clone()), "JBSWY3DPEHPK3PXP");
                assert_eq!(*period, 30);
                assert_eq!(*digits, 6);
                assert_eq!(username, "");
                assert_eq!(*algorithm, OTPHashAlgorithm::Sha1);
                assert!(issuer.is_none());
            }
            _ => panic!("Expected Credential::Passkey"),
        }

        let credential = &item.credentials[2];

        match credential {
            Credential::Passkey(passkey) => {
                assert_eq!(passkey.credential_id.to_string(), "6NiHiekW4ZY8vYHa-ucbvA");
                assert_eq!(passkey.rp_id, "123");
                assert_eq!(passkey.user_name, "");
                assert_eq!(passkey.user_display_name, "");
                assert_eq!(String::from(passkey.user_handle.clone()), "AAECAwQFBg");
                assert_eq!(String::from(passkey.key.clone()), "AAECAwQFBg");
                assert!(passkey.fido2_extensions.is_none());
            }
            _ => panic!("Expected Credential::Passkey"),
        }

        let credential = &item.credentials[3];

        match credential {
            Credential::Note { content } => {
                assert_eq!(content, "My note");
            }
            _ => panic!("Expected Credential::Passkey"),
        }
    }
}