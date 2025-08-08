//! Login credential conversion
//!
//! Handles conversion between internal [Login] and credential exchange [BasicAuthCredential] and
//! [PasskeyCredential].

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bitwarden_core::MissingFieldError;
use bitwarden_fido::{string_to_guid_bytes, InvalidGuid};
use bitwarden_vault::FieldType;
use chrono::{DateTime, Utc};
use credential_exchange_format::{
    AndroidAppIdCredential, BasicAuthCredential, CredentialScope, PasskeyCredential,
};
use thiserror::Error;

use crate::{Fido2Credential, Field, Login, LoginUri};

/// Prefix that indicates the URL is an Android app scheme.
const ANDROID_APP_SCHEME: &str = "androidapp://";

pub(super) fn to_login(
    creation_date: DateTime<Utc>,
    basic_auth: Option<&BasicAuthCredential>,
    passkey: Option<&PasskeyCredential>,
    scope: Option<&CredentialScope>,
) -> Login {
    Login {
        username: basic_auth.and_then(|v| v.username.clone().map(|v| v.into())),
        password: basic_auth.and_then(|v| v.password.clone().map(|u| u.into())),
        login_uris: scope.map(to_uris).unwrap_or_default(),
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
                user_name: Some(p.username.clone()),
                counter: 0,
                rp_name: Some(p.rp_id.clone()),
                user_display_name: Some(p.user_display_name.clone()),
                discoverable: "true".to_string(),
                creation_date,
            }]
        }),
    }
}

/// Converts a `CredentialScope` to a vector of `LoginUri` objects.
///
/// This is used for login credentials.
fn to_uris(scope: &CredentialScope) -> Vec<LoginUri> {
    let urls = scope.urls.iter().map(|u| LoginUri {
        uri: Some(u.clone()),
        r#match: None,
    });

    let android_apps = scope.android_apps.iter().map(|a| LoginUri {
        uri: Some(format!("{ANDROID_APP_SCHEME}{}", a.bundle_id)),
        r#match: None,
    });

    urls.chain(android_apps).collect()
}

/// Converts a `CredentialScope` to a vector of `Field` objects.
///
/// This is used for non-login credentials.
pub(crate) fn to_fields(scope: &CredentialScope) -> Vec<Field> {
    let urls = scope.urls.iter().enumerate().map(|(i, u)| Field {
        name: Some(format!("Url {}", i + 1)),
        value: Some(u.clone()),
        r#type: FieldType::Text as u8,
        linked_id: None,
    });

    let android_apps = scope.android_apps.iter().enumerate().map(|(i, a)| Field {
        name: Some(format!("Android App {}", i + 1)),
        value: Some(a.bundle_id.clone()),
        r#type: FieldType::Text as u8,
        linked_id: None,
    });

    urls.chain(android_apps).collect()
}

impl From<Login> for BasicAuthCredential {
    fn from(login: Login) -> Self {
        BasicAuthCredential {
            username: login.username.map(|v| v.into()),
            password: login.password.map(|v| v.into()),
        }
    }
}

impl From<Login> for CredentialScope {
    fn from(login: Login) -> Self {
        let (android_uris, urls): (Vec<_>, Vec<_>) = login
            .login_uris
            .into_iter()
            .filter_map(|u| u.uri)
            .partition(|uri| uri.starts_with(ANDROID_APP_SCHEME));

        let android_apps = android_uris
            .into_iter()
            .map(|uri| {
                let rest = uri.trim_start_matches(ANDROID_APP_SCHEME);
                AndroidAppIdCredential {
                    bundle_id: rest.to_string(),
                    certificate: None,
                    name: None,
                }
            })
            .collect();

        CredentialScope { urls, android_apps }
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
            username: value.user_name.unwrap_or_default(),
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
        assert_eq!(username.value.0, "test@bitwarden.com");
        assert!(username.label.is_none());

        let password = basic_auth.password.as_ref().unwrap();
        assert_eq!(password.value.0, "asdfasdfasdf");
        assert!(password.label.is_none());
    }

    #[test]
    fn test_credential_scope() {
        let login = Login {
            username: None,
            password: None,
            login_uris: vec![LoginUri {
                uri: Some("https://vault.bitwarden.com".to_string()),
                r#match: None,
            }],
            totp: None,
            fido2_credentials: None,
        };

        let scope: CredentialScope = login.into();

        assert_eq!(scope.urls, vec!["https://vault.bitwarden.com".to_string()]);
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
        assert_eq!(passkey.username, "");
        assert_eq!(passkey.user_display_name, "");
        assert_eq!(String::from(passkey.user_handle.clone()), "AAECAwQFBg");
        assert_eq!(String::from(passkey.key.clone()), "AAECAwQFBg");
        assert!(passkey.fido2_extensions.is_none());
    }

    #[test]
    fn test_to_uris_with_urls_only() {
        let scope = CredentialScope {
            urls: vec![
                "https://vault.bitwarden.com".to_string(),
                "https://bitwarden.com".to_string(),
            ],
            android_apps: vec![],
        };

        let uris = to_uris(&scope);

        assert_eq!(
            uris,
            vec![
                LoginUri {
                    uri: Some("https://vault.bitwarden.com".to_string()),
                    r#match: None
                },
                LoginUri {
                    uri: Some("https://bitwarden.com".to_string()),
                    r#match: None
                },
            ]
        );
    }

    #[test]
    fn test_to_uris_with_android_apps_only() {
        let scope = CredentialScope {
            urls: vec![],
            android_apps: vec![
                credential_exchange_format::AndroidAppIdCredential {
                    bundle_id: "com.bitwarden.app".to_string(),
                    certificate: None,
                    name: None,
                },
                credential_exchange_format::AndroidAppIdCredential {
                    bundle_id: "com.example.app".to_string(),
                    certificate: None,
                    name: None,
                },
            ],
        };

        let uris = to_uris(&scope);

        assert_eq!(
            uris,
            vec![
                LoginUri {
                    uri: Some("androidapp://com.bitwarden.app".to_string()),
                    r#match: None
                },
                LoginUri {
                    uri: Some("androidapp://com.example.app".to_string()),
                    r#match: None
                },
            ]
        );
    }

    #[test]
    fn test_to_uris_with_mixed_urls_and_android_apps() {
        let scope = CredentialScope {
            urls: vec![
                "https://vault.bitwarden.com".to_string(),
                "https://bitwarden.com".to_string(),
            ],
            android_apps: vec![
                credential_exchange_format::AndroidAppIdCredential {
                    bundle_id: "com.bitwarden.app".to_string(),
                    certificate: None,
                    name: None,
                },
                credential_exchange_format::AndroidAppIdCredential {
                    bundle_id: "com.example.app".to_string(),
                    certificate: None,
                    name: None,
                },
            ],
        };

        let uris = to_uris(&scope);

        assert_eq!(
            uris,
            vec![
                LoginUri {
                    uri: Some("https://vault.bitwarden.com".to_string()),
                    r#match: None
                },
                LoginUri {
                    uri: Some("https://bitwarden.com".to_string()),
                    r#match: None
                },
                LoginUri {
                    uri: Some("androidapp://com.bitwarden.app".to_string()),
                    r#match: None
                },
                LoginUri {
                    uri: Some("androidapp://com.example.app".to_string()),
                    r#match: None
                },
            ]
        );
    }

    #[test]
    fn test_to_uris_with_empty_scope() {
        let scope = CredentialScope {
            urls: vec![],
            android_apps: vec![],
        };

        let uris = to_uris(&scope);

        assert!(uris.is_empty());
    }

    #[test]
    fn test_credential_scope_with_android_apps_only() {
        let login = Login {
            username: None,
            password: None,
            login_uris: vec![
                LoginUri {
                    uri: Some("androidapp://com.bitwarden.app".to_string()),
                    r#match: None,
                },
                LoginUri {
                    uri: Some("androidapp://com.example.app".to_string()),
                    r#match: None,
                },
            ],
            totp: None,
            fido2_credentials: None,
        };

        let scope: CredentialScope = login.into();
        assert!(scope.urls.is_empty());
        assert_eq!(scope.android_apps.len(), 2);
        assert_eq!(scope.android_apps[0].bundle_id, "com.bitwarden.app");
        assert_eq!(scope.android_apps[1].bundle_id, "com.example.app");
    }

    #[test]
    fn test_credential_scope_with_mixed_urls_and_android_apps() {
        let login = Login {
            username: None,
            password: None,
            login_uris: vec![
                LoginUri {
                    uri: Some("https://vault.bitwarden.com".to_string()),
                    r#match: None,
                },
                LoginUri {
                    uri: Some("androidapp://com.bitwarden.app".to_string()),
                    r#match: None,
                },
                LoginUri {
                    uri: Some("https://bitwarden.com".to_string()),
                    r#match: None,
                },
                LoginUri {
                    uri: Some("androidapp://com.example.app".to_string()),
                    r#match: None,
                },
            ],
            totp: None,
            fido2_credentials: None,
        };

        let scope: CredentialScope = login.into();
        assert_eq!(
            scope.urls,
            vec![
                "https://vault.bitwarden.com".to_string(),
                "https://bitwarden.com".to_string(),
            ]
        );
        assert_eq!(scope.android_apps.len(), 2);
        assert_eq!(scope.android_apps[0].bundle_id, "com.bitwarden.app");
        assert_eq!(scope.android_apps[1].bundle_id, "com.example.app");
    }

    #[test]
    fn test_to_fields() {
        let scope = CredentialScope {
            urls: vec![
                "https://vault.bitwarden.com".to_string(),
                "https://bitwarden.com".to_string(),
            ],
            android_apps: vec![
                credential_exchange_format::AndroidAppIdCredential {
                    bundle_id: "com.bitwarden.app".to_string(),
                    certificate: None,
                    name: None,
                },
                credential_exchange_format::AndroidAppIdCredential {
                    bundle_id: "com.example.app".to_string(),
                    certificate: None,
                    name: None,
                },
            ],
        };

        let fields = to_fields(&scope);
        assert_eq!(
            fields,
            vec![
                Field {
                    name: Some("Url 1".to_string()),
                    value: Some("https://vault.bitwarden.com".to_string()),
                    r#type: FieldType::Text as u8,
                    linked_id: None,
                },
                Field {
                    name: Some("Url 2".to_string()),
                    value: Some("https://bitwarden.com".to_string()),
                    r#type: FieldType::Text as u8,
                    linked_id: None,
                },
                Field {
                    name: Some("Android App 1".to_string()),
                    value: Some("com.bitwarden.app".to_string()),
                    r#type: FieldType::Text as u8,
                    linked_id: None,
                },
                Field {
                    name: Some("Android App 2".to_string()),
                    value: Some("com.example.app".to_string()),
                    r#type: FieldType::Text as u8,
                    linked_id: None,
                },
            ]
        );
    }
}
