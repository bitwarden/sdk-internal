use bitwarden_vault::{Totp, TotpAlgorithm};
use credential_exchange_format::{
    Account as CxfAccount, Credential, CustomFieldsCredential, EditableFieldValue, Item,
    NoteCredential, OTPHashAlgorithm, TotpCredential,
};
use uuid::Uuid;
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

use crate::{
    Cipher, CipherType, Login,
    cxf::{CxfError, editable_field::field_to_editable_field_value},
};

/// Temporary struct to hold metadata related to current account
///
/// Eventually the SDK itself should have this state and we get rid of this struct.
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct Account {
    id: Uuid,
    email: String,
    name: Option<String>,
}

/// Builds a Credential Exchange Format (CXF) payload
pub(crate) fn build_cxf(account: Account, ciphers: Vec<Cipher>) -> Result<String, CxfError> {
    let items: Vec<Item> = ciphers
        .into_iter()
        .flat_map(|cipher| cipher.try_into())
        .collect();

    let account = CxfAccount {
        id: account.id.as_bytes().as_slice().into(),
        username: "".to_owned(),
        email: account.email,
        full_name: account.name,
        collections: vec![], // TODO: Add support for folders
        items,
        extensions: None,
    };

    Ok(serde_json::to_string(&account)?)
}

impl TryFrom<Cipher> for Item {
    type Error = CxfError;

    fn try_from(value: Cipher) -> Result<Self, Self::Error> {
        let mut credentials: Vec<Credential> = value.r#type.clone().into();

        if let Some(note) = value.notes {
            credentials.push(Credential::Note(Box::new(NoteCredential {
                content: note.into(),
            })));
        }

        // Convert Bitwarden custom fields to CustomFieldsCredential
        if !value.fields.is_empty() {
            let custom_fields: Vec<EditableFieldValue> = value
                .fields
                .into_iter()
                .filter_map(field_to_editable_field_value)
                .collect();

            if !custom_fields.is_empty() {
                credentials.push(Credential::CustomFields(Box::new(CustomFieldsCredential {
                    id: None,
                    label: None,
                    fields: custom_fields,
                    extensions: vec![],
                })));
            }
        }

        Ok(Self {
            id: value.id.as_bytes().as_slice().into(),
            creation_at: Some(value.creation_date.timestamp() as u64),
            modified_at: Some(value.revision_date.timestamp() as u64),
            title: value.name,
            subtitle: None,
            favorite: Some(value.favorite),
            credentials,
            tags: None,
            extensions: None,
            scope: match value.r#type {
                CipherType::Login(login) => Some((*login).into()),
                _ => None,
            },
        })
    }
}

impl From<CipherType> for Vec<Credential> {
    fn from(value: CipherType) -> Self {
        match value {
            CipherType::Login(login) => (*login).into(),
            CipherType::Card(card) => (*card).into(),
            CipherType::Identity(identity) => (*identity).into(),
            // Secure Notes only contains a note field which is handled by `TryFrom<Cipher> for
            // Item`.
            CipherType::SecureNote(_) => vec![],
            CipherType::SshKey(ssh) => (*ssh).try_into().unwrap_or_default(),
        }
    }
}

/// Convert a `Login` struct into the appropriate `Credential`s.
impl From<Login> for Vec<Credential> {
    fn from(login: Login) -> Self {
        let mut credentials = vec![];

        if login.username.is_some() || login.password.is_some() || !login.login_uris.is_empty() {
            credentials.push(Credential::BasicAuth(Box::new(login.clone().into())));
        }

        if let Some(totp) = login.totp.and_then(|t| t.parse::<Totp>().ok()) {
            credentials.push(Credential::Totp(Box::new(convert_totp(totp))));
        }

        if let Some(fido2_credentials) = login.fido2_credentials {
            credentials.extend(
                fido2_credentials
                    .into_iter()
                    .filter_map(|fido2_credential| fido2_credential.try_into().ok())
                    .map(|c| Credential::Passkey(Box::new(c))),
            );
        }

        credentials
    }
}

/// Convert a `Totp` struct into a `TotpCredential` struct
fn convert_totp(totp: Totp) -> TotpCredential {
    // TODO(PM-15389): Properly set username/issuer.
    TotpCredential {
        secret: totp.secret.into(),
        period: totp.period as u8,
        digits: totp.digits as u8,
        username: totp.account,
        algorithm: match totp.algorithm {
            TotpAlgorithm::Sha1 => OTPHashAlgorithm::Sha1,
            TotpAlgorithm::Sha256 => OTPHashAlgorithm::Sha256,
            TotpAlgorithm::Sha512 => OTPHashAlgorithm::Sha512,
            TotpAlgorithm::Steam => OTPHashAlgorithm::Unknown("steam".to_string()),
        },
        issuer: totp.issuer,
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{Fido2Credential, Field, LoginUri};

    #[test]
    fn test_convert_totp() {
        let totp = Totp {
            account: Some("test-account@example.com".to_string()),
            algorithm: TotpAlgorithm::Sha1,
            digits: 4,
            issuer: Some("test-issuer".to_string()),
            period: 60,
            secret: "secret".as_bytes().to_vec(),
        };

        let credential = convert_totp(totp);
        assert_eq!(String::from(credential.secret), "ONSWG4TFOQ");
        assert_eq!(credential.period, 60);
        assert_eq!(credential.digits, 4);
        assert_eq!(credential.username.unwrap(), "test-account@example.com");
        assert_eq!(credential.algorithm, OTPHashAlgorithm::Sha1);
        assert_eq!(credential.issuer, Some("test-issuer".to_string()));
    }

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

        let item: Item = cipher.try_into().unwrap();

        assert_eq!(item.id.to_string(), "JcjEFLRGSOmhvbEHALvXQA");
        assert_eq!(item.creation_at, Some(1706613834));
        assert_eq!(item.modified_at, Some(1706623773));
        assert_eq!(item.title, "Bitwarden");
        assert_eq!(item.subtitle, None);
        assert_eq!(item.tags, None);
        assert_eq!(
            item.scope.unwrap().urls,
            vec!["https://vault.bitwarden.com".to_string()]
        );
        assert!(item.extensions.is_none());

        assert_eq!(item.credentials.len(), 5);

        let credential = &item.credentials[0];

        match credential {
            Credential::BasicAuth(basic_auth) => {
                let username = basic_auth.username.as_ref().unwrap();
                assert_eq!(username.value.0, "test@bitwarden.com");
                assert!(username.label.is_none());

                let password = basic_auth.password.as_ref().unwrap();
                assert_eq!(password.value.0, "asdfasdfasdf");
                assert!(password.label.is_none());
            }
            _ => panic!("Expected Credential::BasicAuth"),
        }

        let credential = &item.credentials[1];

        match credential {
            Credential::Totp(totp) => {
                assert_eq!(String::from(totp.secret.clone()), "JBSWY3DPEHPK3PXP");
                assert_eq!(totp.period, 30);
                assert_eq!(totp.digits, 6);
                assert_eq!(totp.username, None);
                assert_eq!(totp.algorithm, OTPHashAlgorithm::Sha1);
                assert!(totp.issuer.is_none());
            }
            _ => panic!("Expected Credential::Passkey"),
        }

        let credential = &item.credentials[2];

        match credential {
            Credential::Passkey(passkey) => {
                assert_eq!(passkey.credential_id.to_string(), "6NiHiekW4ZY8vYHa-ucbvA");
                assert_eq!(passkey.rp_id, "123");
                assert_eq!(passkey.username, "");
                assert_eq!(passkey.user_display_name, "");
                assert_eq!(String::from(passkey.user_handle.clone()), "AAECAwQFBg");
                assert_eq!(String::from(passkey.key.clone()), "AAECAwQFBg");
                assert!(passkey.fido2_extensions.is_none());
            }
            _ => panic!("Expected Credential::Passkey"),
        }

        let credential = &item.credentials[3];

        match credential {
            Credential::Note(n) => {
                assert_eq!(n.content.value.0, "My note");
            }
            _ => panic!("Expected Credential::Note"),
        }

        let credential = &item.credentials[4];

        match credential {
            Credential::CustomFields(custom_fields) => {
                assert_eq!(custom_fields.fields.len(), 5); // Text, Hidden, Boolean true, Boolean false, Linked

                // Check Text field
                match &custom_fields.fields[0] {
                    EditableFieldValue::String(field) => {
                        assert_eq!(field.label.as_ref().unwrap(), "Text");
                        assert_eq!(field.value.0, "A");
                    }
                    _ => panic!("Expected String field"),
                }

                // Check Hidden field
                match &custom_fields.fields[1] {
                    EditableFieldValue::ConcealedString(field) => {
                        assert_eq!(field.label.as_ref().unwrap(), "Hidden");
                        assert_eq!(field.value.0, "B");
                    }
                    _ => panic!("Expected ConcealedString field"),
                }

                // Check Boolean true field
                match &custom_fields.fields[2] {
                    EditableFieldValue::Boolean(field) => {
                        assert_eq!(field.label.as_ref().unwrap(), "Boolean (true)");
                        assert!(field.value.0);
                    }
                    _ => panic!("Expected Boolean field"),
                }

                // Check Boolean false field
                match &custom_fields.fields[3] {
                    EditableFieldValue::Boolean(field) => {
                        assert_eq!(field.label.as_ref().unwrap(), "Boolean (false)");
                        assert!(!field.value.0);
                    }
                    _ => panic!("Expected Boolean field"),
                }

                // Check Linked field
                match &custom_fields.fields[4] {
                    EditableFieldValue::String(field) => {
                        assert_eq!(field.label.as_ref().unwrap(), "Linked");
                        assert_eq!(field.value.0, "101"); // linked_id as string
                    }
                    _ => panic!("Expected String field for Linked"),
                }
            }
            _ => panic!("Expected Credential::CustomFields"),
        }
    }
}
