//! Login credential conversion
//!
//! Handles conversion between internal [Login] and credential exchange [BasicAuthCredential] and
//! [PasskeyCredential].

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bitwarden_core::MissingFieldError;
use bitwarden_crypto::generate_random_bytes;
use bitwarden_fido::{string_to_guid_bytes, InvalidGuid};
use chrono::{DateTime, Utc};
use credential_exchange_types::{
    format::{BasicAuthCredential, EditableField, FieldType, PasskeyCredential},
    B64Url,
};
use thiserror::Error;

use crate::{Fido2Credential, Login, LoginUri};

/// Generate a 32 byte random ID
///
/// TODO: This should be removed shortly.
fn random_id() -> B64Url {
    generate_random_bytes::<[u8; 32]>().as_slice().into()
}

pub(super) fn to_login(
    creation_date: DateTime<Utc>,
    basic_auth: Option<&BasicAuthCredential>,
    passkey: Option<&PasskeyCredential>,
) -> Login {
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
                creation_date,
            }]
        }),
    };
    login
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
            user_name: value.user_name.unwrap_or_default(),
            user_display_name: value.user_display_name.unwrap_or_default(),
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
    use super::*;
    use crate::LoginUri;

    #[test]
    fn test_basic_auth() {
        let login = Login {
            username: Some("test@bitwarden.com".to_string()),
            password: Some("asdfasdfasdf".to_string()),
            login_uris: vec![LoginUri {
                uri: Some("https://vault.bitwarden.com".to_string()),
                r#match: None,
            }],
            totp: None,
            fido2_credentials: None,
        };

        let basic_auth: BasicAuthCredential = login.into();

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

    #[test]
    fn test_passkey() {
        let credential = Fido2Credential {
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
        };

        let passkey: PasskeyCredential = credential.try_into().unwrap();

        assert_eq!(passkey.credential_id.to_string(), "6NiHiekW4ZY8vYHa-ucbvA");
        assert_eq!(passkey.rp_id, "123");
        assert_eq!(passkey.user_name, "");
        assert_eq!(passkey.user_display_name, "");
        assert_eq!(String::from(passkey.user_handle.clone()), "AAECAwQFBg");
        assert_eq!(String::from(passkey.key.clone()), "AAECAwQFBg");
        assert!(passkey.fido2_extensions.is_none());
    }
}
