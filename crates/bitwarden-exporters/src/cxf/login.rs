//! Login credential conversion
//!
//! Handles conversion between internal [Login] and credential exchange [BasicAuthCredential] and
//! [PasskeyCredential].

use bitwarden_core::MissingFieldError;
use bitwarden_fido::{InvalidGuidError, string_to_guid_bytes};
use bitwarden_vault::{FieldType, Totp, TotpAlgorithm};
use chrono::{DateTime, Utc};
use credential_exchange_format::{
    AndroidAppIdCredential, B64Url, BasicAuthCredential, CredentialScope, NotB64UrlEncoded,
    OTPHashAlgorithm, PasskeyCredential, TotpCredential,
};
use thiserror::Error;

use crate::{Fido2Credential, Field, Login, LoginUri};

/// Prefix that indicates the URL is an Android app scheme.
const ANDROID_APP_SCHEME: &str = "androidapp://";

/// Convert CXF OTPHashAlgorithm to Bitwarden's TotpAlgorithm
/// Handles standard algorithms and special cases like Steam
fn convert_otp_algorithm(algorithm: &OTPHashAlgorithm) -> TotpAlgorithm {
    match algorithm {
        OTPHashAlgorithm::Sha1 => TotpAlgorithm::Sha1,
        OTPHashAlgorithm::Sha256 => TotpAlgorithm::Sha256,
        OTPHashAlgorithm::Sha512 => TotpAlgorithm::Sha512,
        OTPHashAlgorithm::Unknown(algo) if algo == "steam" => TotpAlgorithm::Steam,
        OTPHashAlgorithm::Unknown(_) | _ => TotpAlgorithm::Sha1, /* Default to SHA1 for unknown
                                                                  * algorithms */
    }
}

/// Convert CXF TotpCredential to Bitwarden's Totp struct
/// This ensures we use the exact same encoding and formatting as Bitwarden's core implementation
fn totp_credential_to_totp(cxf_totp: &TotpCredential) -> Totp {
    let algorithm = convert_otp_algorithm(&cxf_totp.algorithm);

    let secret_bytes: Vec<u8> = cxf_totp.secret.clone().into();

    Totp {
        account: cxf_totp.username.clone(),
        algorithm,
        digits: cxf_totp.digits as u32,
        issuer: cxf_totp.issuer.clone(),
        period: cxf_totp.period as u32,
        secret: secret_bytes,
    }
}

pub(super) fn to_login(
    creation_date: DateTime<Utc>,
    basic_auth: Option<&BasicAuthCredential>,
    passkey: Option<&PasskeyCredential>,
    totp: Option<&TotpCredential>,
    scope: Option<&CredentialScope>,
) -> Login {
    // Use basic_auth username first, fallback to non-empty passkey username
    let username = basic_auth
        .and_then(|v| v.username.clone().map(Into::into))
        .or_else(|| {
            passkey
                .filter(|p| !p.username.is_empty())
                .map(|p| p.username.clone())
        });

    // Use scope URIs first, fallback to passkey rp_id
    let login_uris = scope
        .map(to_uris)
        .or_else(|| passkey.map(|p| vec![passkey_rp_id_to_uri(&p.rp_id)]))
        .unwrap_or_default();

    Login {
        username,
        password: basic_auth.and_then(|v| v.password.clone().map(|u| u.into())),
        login_uris,
        totp: totp.map(|t| totp_credential_to_totp(t).to_string()),
        fido2_credentials: passkey.map(|p| {
            vec![Fido2Credential {
                credential_id: format!("b64.{}", p.credential_id),
                key_type: "public-key".to_string(),
                key_algorithm: "ECDSA".to_string(),
                key_curve: "P-256".to_string(),
                key_value: p.key.to_string(),
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

/// Creates a LoginUri from a URL string
fn create_login_uri(uri: String) -> LoginUri {
    LoginUri {
        uri: Some(uri),
        r#match: None,
    }
}

/// Creates URIs from a passkey's rp_id, adding https:// prefix for domain-like strings
fn passkey_rp_id_to_uri(rp_id: &str) -> LoginUri {
    let uri = if rp_id.contains('.') && !rp_id.starts_with("http") {
        format!("https://{rp_id}")
    } else {
        rp_id.to_string()
    };
    create_login_uri(uri)
}

/// Converts a `CredentialScope` to a vector of `LoginUri` objects.
///
/// This is used for login credentials.
fn to_uris(scope: &CredentialScope) -> Vec<LoginUri> {
    let urls = scope.urls.iter().map(|u| create_login_uri(u.clone()));

    let android_apps = scope
        .android_apps
        .iter()
        .map(|a| create_login_uri(format!("{ANDROID_APP_SCHEME}{}", a.bundle_id)));

    urls.chain(android_apps).collect()
}

/// Converts a `CredentialScope` to a vector of `Field` objects.
///
/// This is used for non-login credentials.
#[allow(unused)]
pub(super) fn to_fields(scope: &CredentialScope) -> Vec<Field> {
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
    InvalidGuid(InvalidGuidError),
    #[error(transparent)]
    MissingField(MissingFieldError),
    #[error("Data isn't base64url encoded")]
    InvalidBase64(NotB64UrlEncoded),
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
                .map(|v| B64Url::try_from(v.as_str()))
                .transpose()
                .map_err(PasskeyError::InvalidBase64)?
                .ok_or(PasskeyError::MissingField(MissingFieldError("user_handle")))?,
            key: B64Url::try_from(value.key_value.as_str()).map_err(PasskeyError::InvalidBase64)?,
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

    // TOTP tests
    #[test]
    fn test_totp_credential_to_totp_basic() {
        let totp = TotpCredential {
            secret: "Hello World!".as_bytes().to_vec().into(),
            period: 30,
            digits: 6,
            username: Some("test@example.com".to_string()),
            algorithm: OTPHashAlgorithm::Sha1,
            issuer: Some("Example".to_string()),
        };

        let bitwarden_totp = totp_credential_to_totp(&totp);
        let otpauth = bitwarden_totp.to_string();

        assert!(otpauth.starts_with("otpauth://totp/Example:test%40example%2Ecom?secret="));
        assert!(otpauth.contains("&issuer=Example"));
        // Default period (30) and digits (6) and algorithm (SHA1) should not be included
        assert!(!otpauth.contains("&period=30"));
        assert!(!otpauth.contains("&digits=6"));
        assert!(!otpauth.contains("&algorithm=SHA1"));
    }

    #[test]
    fn test_totp_credential_to_totp_custom_parameters() {
        let totp = TotpCredential {
            secret: "Hello World!".as_bytes().to_vec().into(),
            period: 60,
            digits: 8,
            username: Some("user".to_string()),
            algorithm: OTPHashAlgorithm::Sha256,
            issuer: Some("Custom Issuer".to_string()),
        };

        let bitwarden_totp = totp_credential_to_totp(&totp);
        let otpauth = bitwarden_totp.to_string();

        assert!(otpauth.contains("Custom%20Issuer:user"));
        assert!(otpauth.contains("&issuer=Custom%20Issuer"));
        assert!(otpauth.contains("&period=60"));
        assert!(otpauth.contains("&digits=8"));
        assert!(otpauth.contains("&algorithm=SHA256"));
    }

    // Algorithm conversion tests
    #[test]
    fn test_convert_otp_algorithm_sha1() {
        let result = convert_otp_algorithm(&OTPHashAlgorithm::Sha1);
        assert_eq!(result, TotpAlgorithm::Sha1);
    }

    #[test]
    fn test_convert_otp_algorithm_sha256() {
        let result = convert_otp_algorithm(&OTPHashAlgorithm::Sha256);
        assert_eq!(result, TotpAlgorithm::Sha256);
    }

    #[test]
    fn test_convert_otp_algorithm_sha512() {
        let result = convert_otp_algorithm(&OTPHashAlgorithm::Sha512);
        assert_eq!(result, TotpAlgorithm::Sha512);
    }

    #[test]
    fn test_convert_otp_algorithm_steam() {
        let result = convert_otp_algorithm(&OTPHashAlgorithm::Unknown("steam".to_string()));
        assert_eq!(result, TotpAlgorithm::Steam);
    }

    #[test]
    fn test_convert_otp_algorithm_steam_case_sensitive() {
        // Test that "steam" is case-sensitive
        let result = convert_otp_algorithm(&OTPHashAlgorithm::Unknown("Steam".to_string()));
        assert_eq!(result, TotpAlgorithm::Sha1); // will default to SHA1
    }

    #[test]
    fn test_convert_otp_algorithm_unknown_empty() {
        let result = convert_otp_algorithm(&OTPHashAlgorithm::Unknown("".to_string()));
        assert_eq!(result, TotpAlgorithm::Sha1); // will default to SHA1
    }

    #[test]
    fn test_convert_otp_algorithm_unknown_md5() {
        // Test an algorithm that might exist in other systems but isn't supported
        let result = convert_otp_algorithm(&OTPHashAlgorithm::Unknown("md5".to_string()));
        assert_eq!(result, TotpAlgorithm::Sha1); // will default to SHA1
    }

    #[test]
    fn test_convert_otp_algorithm_unknown_whitespace() {
        // Test steam with whitespace (will not match)
        let result = convert_otp_algorithm(&OTPHashAlgorithm::Unknown(" steam ".to_string()));
        assert_eq!(result, TotpAlgorithm::Sha1); // will default to SHA1
    }

    // Tests for the new helper functions
    #[test]
    fn test_passkey_rp_id_to_uri_with_domain() {
        let uri = passkey_rp_id_to_uri("example.com");
        assert_eq!(uri.uri, Some("https://example.com".to_string()));
        assert_eq!(uri.r#match, None);
    }

    #[test]
    fn test_passkey_rp_id_to_uri_with_https() {
        let uri = passkey_rp_id_to_uri("https://example.com");
        assert_eq!(uri.uri, Some("https://example.com".to_string()));
        assert_eq!(uri.r#match, None);
    }

    #[test]
    fn test_passkey_rp_id_to_uri_without_domain() {
        let uri = passkey_rp_id_to_uri("localhost");
        assert_eq!(uri.uri, Some("localhost".to_string()));
        assert_eq!(uri.r#match, None);
    }

    #[test]
    fn test_create_login_uri() {
        let uri = create_login_uri("https://test.example".to_string());
        assert_eq!(uri.uri, Some("https://test.example".to_string()));
        assert_eq!(uri.r#match, None);
    }
}
