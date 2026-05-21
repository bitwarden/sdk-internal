use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serializer;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    Card, Cipher, CipherType, Fido2Credential, Field, Folder, Identity, Login, LoginUri,
    PasswordHistory, SecureNote, SshKey,
};

/// Serialize a `DateTime<Utc>` with millisecond precision to match the web exporter, which uses
/// JavaScript's `Date.toISOString()` format.
fn rfc3339_millis_serialize<S: Serializer>(date: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&date.to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// Serialize an optional `DateTime<Utc>` with millisecond precision when present.
fn serialize_opt_date_millis_rfc3339_millis<S: Serializer>(
    date: &Option<DateTime<Utc>>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match date {
        Some(d) => s.serialize_str(&d.to_rfc3339_opts(SecondsFormat::Millis, true)),
        None => s.serialize_none(),
    }
}

#[derive(Error, Debug)]
pub enum JsonError {
    #[error("JSON error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub(crate) fn export_json(folders: Vec<Folder>, ciphers: Vec<Cipher>) -> Result<String, JsonError> {
    let export = JsonExport {
        encrypted: false,
        folders: folders.into_iter().map(|f| f.into()).collect(),
        items: ciphers
            .into_iter()
            .filter(|c| {
                !matches!(
                    c.r#type,
                    CipherType::BankAccount | CipherType::Passport | CipherType::DriversLicense
                )
            })
            .map(|c| c.into())
            .collect(),
    };

    Ok(serde_json::to_string_pretty(&export)?)
}

/// JSON export format. These are intentionally decoupled from the internal data structures to
/// ensure internal changes are not reflected in the public exports.
///
/// Be careful about changing these structs to maintain compatibility with old exporters/importers.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonExport {
    encrypted: bool,
    folders: Vec<JsonFolder>,
    items: Vec<JsonCipher>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonFolder {
    id: Uuid,
    name: String,
}

impl From<Folder> for JsonFolder {
    fn from(folder: Folder) -> Self {
        JsonFolder {
            id: folder.id,
            name: folder.name,
        }
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonCipher {
    id: Uuid,
    folder_id: Option<Uuid>,
    // Organizational IDs which are always empty in personal exports
    organization_id: Option<Uuid>,
    collection_ids: Option<Vec<Uuid>>,

    name: String,
    notes: Option<String>,

    r#type: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<JsonLogin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<JsonIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    card: Option<JsonCard>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secure_note: Option<JsonSecureNote>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_key: Option<JsonSshKey>,

    favorite: bool,
    reprompt: u8,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    fields: Vec<JsonField>,
    password_history: Option<Vec<JsonPasswordHistory>>,

    #[serde(serialize_with = "rfc3339_millis_serialize")]
    revision_date: DateTime<Utc>,
    #[serde(serialize_with = "rfc3339_millis_serialize")]
    creation_date: DateTime<Utc>,
    #[serde(serialize_with = "serialize_opt_date_millis_rfc3339_millis")]
    deleted_date: Option<DateTime<Utc>>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonLogin {
    username: Option<String>,
    password: Option<String>,
    uris: Vec<JsonLoginUri>,
    totp: Option<String>,
    fido2_credentials: Vec<JsonFido2Credential>,
}

impl From<Login> for JsonLogin {
    fn from(login: Login) -> Self {
        JsonLogin {
            username: login.username,
            password: login.password,
            uris: login.login_uris.into_iter().map(|u| u.into()).collect(),
            totp: login.totp,
            fido2_credentials: login
                .fido2_credentials
                .unwrap_or_default()
                .into_iter()
                .map(|c| c.into())
                .collect(),
        }
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonFido2Credential {
    credential_id: String,
    key_type: String,
    key_algorithm: String,
    key_curve: String,
    key_value: String,
    rp_id: String,
    user_handle: Option<String>,
    user_name: Option<String>,
    // Serialized as a string for parity with the web exporter.
    counter: String,
    rp_name: Option<String>,
    user_display_name: Option<String>,
    // Serialized as a string for parity with the web exporter.
    discoverable: String,
    #[serde(serialize_with = "rfc3339_millis_serialize")]
    creation_date: DateTime<Utc>,
}

impl From<Fido2Credential> for JsonFido2Credential {
    fn from(credential: Fido2Credential) -> Self {
        JsonFido2Credential {
            credential_id: credential.credential_id,
            key_type: credential.key_type,
            key_algorithm: credential.key_algorithm,
            key_curve: credential.key_curve,
            key_value: credential.key_value,
            rp_id: credential.rp_id,
            user_handle: credential.user_handle,
            user_name: credential.user_name,
            counter: credential.counter.to_string(),
            rp_name: credential.rp_name,
            user_display_name: credential.user_display_name,
            discoverable: credential.discoverable,
            creation_date: credential.creation_date,
        }
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonPasswordHistory {
    password: String,
    #[serde(serialize_with = "rfc3339_millis_serialize")]
    last_used_date: DateTime<Utc>,
}

impl From<PasswordHistory> for JsonPasswordHistory {
    fn from(history: PasswordHistory) -> Self {
        JsonPasswordHistory {
            password: history.password,
            last_used_date: history.last_used_date,
        }
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonLoginUri {
    uri: Option<String>,
    r#match: Option<u8>,
}

impl From<LoginUri> for JsonLoginUri {
    fn from(login_uri: LoginUri) -> Self {
        JsonLoginUri {
            uri: login_uri.uri,
            r#match: login_uri.r#match,
        }
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonSecureNote {
    r#type: u8,
}

impl From<SecureNote> for JsonSecureNote {
    fn from(note: SecureNote) -> Self {
        JsonSecureNote {
            r#type: note.r#type as u8,
        }
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonCard {
    cardholder_name: Option<String>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
    brand: Option<String>,
    number: Option<String>,
}

impl From<Card> for JsonCard {
    fn from(card: Card) -> Self {
        JsonCard {
            cardholder_name: card.cardholder_name,
            exp_month: card.exp_month,
            exp_year: card.exp_year,
            code: card.code,
            brand: card.brand,
            number: card.number,
        }
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonIdentity {
    title: Option<String>,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    address1: Option<String>,
    address2: Option<String>,
    address3: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    company: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    ssn: Option<String>,
    username: Option<String>,
    passport_number: Option<String>,
    license_number: Option<String>,
}

impl From<Identity> for JsonIdentity {
    fn from(identity: Identity) -> Self {
        JsonIdentity {
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

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonSshKey {
    private_key: String,
    public_key: String,
    key_fingerprint: String,
}

impl From<SshKey> for JsonSshKey {
    fn from(ssh_key: SshKey) -> Self {
        JsonSshKey {
            private_key: ssh_key.private_key,
            public_key: ssh_key.public_key,
            key_fingerprint: ssh_key.fingerprint,
        }
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonField {
    name: Option<String>,
    value: Option<String>,
    r#type: u8,
    linked_id: Option<u32>,
}

impl From<Field> for JsonField {
    fn from(field: Field) -> Self {
        JsonField {
            name: field.name,
            value: field.value,
            r#type: field.r#type,
            linked_id: field.linked_id,
        }
    }
}

impl From<Cipher> for JsonCipher {
    fn from(cipher: Cipher) -> Self {
        let r#type = match cipher.r#type {
            CipherType::Login(_) => 1,
            CipherType::SecureNote(_) => 2,
            CipherType::Card(_) => 3,
            CipherType::Identity(_) => 4,
            CipherType::SshKey(_) => 5,
            // BankAccount/Passport/DriversLicense ciphers should be filtered out before reaching
            // this point
            CipherType::BankAccount | CipherType::Passport | CipherType::DriversLicense => {
                unreachable!(
                    "This cipher type is not supported for export and should be filtered out"
                )
            }
        };

        let (login, secure_note, card, identity, ssh_key) = match cipher.r#type {
            CipherType::Login(l) => (Some((*l).into()), None, None, None, None),
            CipherType::SecureNote(s) => (None, Some((*s).into()), None, None, None),
            CipherType::Card(c) => (None, None, Some((*c).into()), None, None),
            CipherType::Identity(i) => (None, None, None, Some((*i).into()), None),
            CipherType::SshKey(ssh) => (None, None, None, None, Some((*ssh).into())),
            CipherType::BankAccount | CipherType::Passport | CipherType::DriversLicense => {
                unreachable!(
                    "This cipher type is not supported for export and should be filtered out"
                )
            }
        };

        JsonCipher {
            id: cipher.id,
            folder_id: cipher.folder_id,
            organization_id: None,
            collection_ids: None,
            name: cipher.name,
            notes: cipher.notes,
            r#type,
            login,
            identity,
            card,
            secure_note,
            ssh_key,
            favorite: cipher.favorite,
            reprompt: cipher.reprompt,
            fields: cipher.fields.into_iter().map(|f| f.into()).collect(),
            password_history: cipher
                .password_history
                .map(|h| h.into_iter().map(|p| p.into()).collect()),
            revision_date: cipher.revision_date,
            creation_date: cipher.creation_date,
            deleted_date: cipher.deleted_date,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Read, path::PathBuf};

    use super::*;
    use crate::{Cipher, Fido2Credential, Field, LoginUri, PasswordHistory, SecureNoteType};

    #[test]
    fn test_convert_login() {
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
                fido2_credentials: None,
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

            password_history: None,
            revision_date: "2024-01-30T14:09:33.753Z".parse().unwrap(),
            creation_date: "2024-01-30T11:23:54.416Z".parse().unwrap(),
            deleted_date: None,
        };

        let json = serde_json::to_string(&JsonCipher::from(cipher)).unwrap();

        let expected = r#"{
            "passwordHistory": null,
            "revisionDate": "2024-01-30T14:09:33.753Z",
            "creationDate": "2024-01-30T11:23:54.416Z",
            "deletedDate": null,
            "id": "25c8c414-b446-48e9-a1bd-b10700bbd740",
            "organizationId": null,
            "folderId": "942e2984-1b9a-453b-b039-b107012713b9",
            "type": 1,
            "reprompt": 0,
            "name": "Bitwarden",
            "notes": "My note",
            "favorite": true,
            "fields": [
              {
                "name": "Text",
                "value": "A",
                "type": 0,
                "linkedId": null
              },
              {
                "name": "Hidden",
                "value": "B",
                "type": 1,
                "linkedId": null
              },
              {
                "name": "Boolean (true)",
                "value": "true",
                "type": 2,
                "linkedId": null
              },
              {
                "name": "Boolean (false)",
                "value": "false",
                "type": 2,
                "linkedId": null
              },
              {
                "name": "Linked",
                "value": null,
                "type": 3,
                "linkedId": 101
              }
            ],
            "login": {
              "fido2Credentials": [],
              "uris": [
                {
                  "match": null,
                  "uri": "https://vault.bitwarden.com"
                }
              ],
              "username": "test@bitwarden.com",
              "password": "asdfasdfasdf",
              "totp": "ABC"
            },
            "collectionIds": null
          }"#;

        assert_eq!(
            json.parse::<serde_json::Value>().unwrap(),
            expected.parse::<serde_json::Value>().unwrap()
        )
    }

    #[test]
    fn test_convert_secure_note() {
        let cipher = Cipher {
            id: "23f0f877-42b1-4820-a850-b10700bc41eb".parse().unwrap(),
            folder_id: None,

            name: "My secure note".to_string(),
            notes: Some("Very secure!".to_string()),

            r#type: CipherType::SecureNote(Box::new(SecureNote {
                r#type: SecureNoteType::Generic,
            })),

            favorite: false,
            reprompt: 0,

            fields: vec![],

            password_history: None,
            revision_date: "2024-01-30T11:25:25.466Z".parse().unwrap(),
            creation_date: "2024-01-30T11:25:25.466Z".parse().unwrap(),
            deleted_date: None,
        };

        let json = serde_json::to_string(&JsonCipher::from(cipher)).unwrap();

        let expected = r#"{
            "passwordHistory": null,
            "revisionDate": "2024-01-30T11:25:25.466Z",
            "creationDate": "2024-01-30T11:25:25.466Z",
            "deletedDate": null,
            "id": "23f0f877-42b1-4820-a850-b10700bc41eb",
            "organizationId": null,
            "folderId": null,
            "type": 2,
            "reprompt": 0,
            "name": "My secure note",
            "notes": "Very secure!",
            "favorite": false,
            "secureNote": {
              "type": 0
            },
            "collectionIds": null
        }"#;

        assert_eq!(
            json.parse::<serde_json::Value>().unwrap(),
            expected.parse::<serde_json::Value>().unwrap()
        )
    }

    #[test]
    fn test_convert_card() {
        let cipher = Cipher {
            id: "3ed8de45-48ee-4e26-a2dc-b10701276c53".parse().unwrap(),
            folder_id: None,

            name: "My card".to_string(),
            notes: None,

            r#type: CipherType::Card(Box::new(Card {
                cardholder_name: Some("John Doe".to_string()),
                exp_month: Some("1".to_string()),
                exp_year: Some("2032".to_string()),
                code: Some("123".to_string()),
                brand: Some("Visa".to_string()),
                number: Some("4111111111111111".to_string()),
            })),

            favorite: false,
            reprompt: 0,

            fields: vec![],

            password_history: None,
            revision_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            creation_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            deleted_date: None,
        };

        let json = serde_json::to_string(&JsonCipher::from(cipher)).unwrap();

        let expected = r#"{
            "passwordHistory": null,
            "revisionDate": "2024-01-30T17:55:36.150Z",
            "creationDate": "2024-01-30T17:55:36.150Z",
            "deletedDate": null,
            "id": "3ed8de45-48ee-4e26-a2dc-b10701276c53",
            "organizationId": null,
            "folderId": null,
            "type": 3,
            "reprompt": 0,
            "name": "My card",
            "notes": null,
            "favorite": false,
            "card": {
                "cardholderName": "John Doe",
                "brand": "Visa",
                "number": "4111111111111111",
                "expMonth": "1",
                "expYear": "2032",
                "code": "123"
            },
            "collectionIds": null
        }"#;

        assert_eq!(
            json.parse::<serde_json::Value>().unwrap(),
            expected.parse::<serde_json::Value>().unwrap()
        )
    }

    #[test]
    fn test_convert_identity() {
        let cipher = Cipher {
            id: "41cc3bc1-c3d9-4637-876c-b10701273712".parse().unwrap(),
            folder_id: Some("942e2984-1b9a-453b-b039-b107012713b9".parse().unwrap()),

            name: "My identity".to_string(),
            notes: None,

            r#type: CipherType::Identity(Box::new(Identity {
                title: Some("Mr".to_string()),
                first_name: Some("John".to_string()),
                middle_name: None,
                last_name: Some("Doe".to_string()),
                address1: None,
                address2: None,
                address3: None,
                city: None,
                state: None,
                postal_code: None,
                country: None,
                company: Some("Bitwarden".to_string()),
                email: None,
                phone: None,
                ssn: None,
                username: Some("JDoe".to_string()),
                passport_number: None,
                license_number: None,
            })),

            favorite: false,
            reprompt: 0,

            fields: vec![],

            password_history: None,
            revision_date: "2024-01-30T17:54:50.706Z".parse().unwrap(),
            creation_date: "2024-01-30T17:54:50.706Z".parse().unwrap(),
            deleted_date: None,
        };

        let json = serde_json::to_string(&JsonCipher::from(cipher)).unwrap();

        let expected = r#"{
            "passwordHistory": null,
            "revisionDate": "2024-01-30T17:54:50.706Z",
            "creationDate": "2024-01-30T17:54:50.706Z",
            "deletedDate": null,
            "id": "41cc3bc1-c3d9-4637-876c-b10701273712",
            "organizationId": null,
            "folderId": "942e2984-1b9a-453b-b039-b107012713b9",
            "type": 4,
            "reprompt": 0,
            "name": "My identity",
            "notes": null,
            "favorite": false,
            "identity": {
                "title": "Mr",
                "firstName": "John",
                "middleName": null,
                "lastName": "Doe",
                "address1": null,
                "address2": null,
                "address3": null,
                "city": null,
                "state": null,
                "postalCode": null,
                "country": null,
                "company": "Bitwarden",
                "email": null,
                "phone": null,
                "ssn": null,
                "username": "JDoe",
                "passportNumber": null,
                "licenseNumber": null
            },
            "collectionIds": null
        }"#;

        assert_eq!(
            json.parse::<serde_json::Value>().unwrap(),
            expected.parse::<serde_json::Value>().unwrap()
        )
    }

    #[test]
    fn test_convert_ssh_key() {
        let cipher = Cipher {
            id: "23f0f877-42b1-4820-a850-b10700bc41eb".parse().unwrap(),
            folder_id: None,

            name: "My ssh key".to_string(),
            notes: None,

            r#type: CipherType::SshKey(Box::new(SshKey {
                private_key: "private".to_string(),
                public_key: "public".to_string(),
                fingerprint: "fingerprint".to_string(),
            })),

            favorite: false,
            reprompt: 0,

            fields: vec![],

            password_history: None,
            revision_date: "2024-01-30T11:25:25.466Z".parse().unwrap(),
            creation_date: "2024-01-30T11:25:25.466Z".parse().unwrap(),
            deleted_date: None,
        };

        let json = serde_json::to_string(&JsonCipher::from(cipher)).unwrap();

        let expected = r#"{
            "passwordHistory": null,
            "revisionDate": "2024-01-30T11:25:25.466Z",
            "creationDate": "2024-01-30T11:25:25.466Z",
            "deletedDate": null,
            "id": "23f0f877-42b1-4820-a850-b10700bc41eb",
            "organizationId": null,
            "folderId": null,
            "type": 5,
            "reprompt": 0,
            "name": "My ssh key",
            "notes": null,
            "sshKey": {
              "privateKey": "private",
              "publicKey": "public",
              "keyFingerprint": "fingerprint"
            },
            "favorite": false,
            "collectionIds": null
        }"#;

        assert_eq!(
            json.parse::<serde_json::Value>().unwrap(),
            expected.parse::<serde_json::Value>().unwrap()
        )
    }

    #[test]
    pub fn test_export() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("resources");
        d.push("json_export.json");

        let mut file = fs::File::open(d).unwrap();

        let mut expected = String::new();
        file.read_to_string(&mut expected).unwrap();

        let export = export_json(
            vec![Folder {
                id: "942e2984-1b9a-453b-b039-b107012713b9".parse().unwrap(),
                name: "Important".to_string(),
            }],
            vec![
                Cipher {
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
                        fido2_credentials: None,
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

                    password_history: None,
                    revision_date: "2024-01-30T14:09:33.753Z".parse().unwrap(),
                    creation_date: "2024-01-30T11:23:54.416Z".parse().unwrap(),
                    deleted_date: None,
                },
                Cipher {
                    id: "23f0f877-42b1-4820-a850-b10700bc41eb".parse().unwrap(),
                    folder_id: None,

                    name: "My secure note".to_string(),
                    notes: Some("Very secure!".to_string()),

                    r#type: CipherType::SecureNote(Box::new(SecureNote {
                        r#type: SecureNoteType::Generic,
                    })),

                    favorite: false,
                    reprompt: 0,

                    fields: vec![],

                    password_history: None,
                    revision_date: "2024-01-30T11:25:25.466Z".parse().unwrap(),
                    creation_date: "2024-01-30T11:25:25.466Z".parse().unwrap(),
                    deleted_date: None,
                },
                Cipher {
                    id: "3ed8de45-48ee-4e26-a2dc-b10701276c53".parse().unwrap(),
                    folder_id: None,

                    name: "My card".to_string(),
                    notes: None,

                    r#type: CipherType::Card(Box::new(Card {
                        cardholder_name: Some("John Doe".to_string()),
                        exp_month: Some("1".to_string()),
                        exp_year: Some("2032".to_string()),
                        code: Some("123".to_string()),
                        brand: Some("Visa".to_string()),
                        number: Some("4111111111111111".to_string()),
                    })),

                    favorite: false,
                    reprompt: 0,

                    fields: vec![],

                    password_history: None,
                    revision_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
                    creation_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
                    deleted_date: None,
                },
                Cipher {
                    id: "41cc3bc1-c3d9-4637-876c-b10701273712".parse().unwrap(),
                    folder_id: Some("942e2984-1b9a-453b-b039-b107012713b9".parse().unwrap()),

                    name: "My identity".to_string(),
                    notes: None,

                    r#type: CipherType::Identity(Box::new(Identity {
                        title: Some("Mr".to_string()),
                        first_name: Some("John".to_string()),
                        middle_name: None,
                        last_name: Some("Doe".to_string()),
                        address1: None,
                        address2: None,
                        address3: None,
                        city: None,
                        state: None,
                        postal_code: None,
                        country: None,
                        company: Some("Bitwarden".to_string()),
                        email: None,
                        phone: None,
                        ssn: None,
                        username: Some("JDoe".to_string()),
                        passport_number: None,
                        license_number: None,
                    })),

                    favorite: false,
                    reprompt: 0,

                    fields: vec![],

                    password_history: None,
                    revision_date: "2024-01-30T17:54:50.706Z".parse().unwrap(),
                    creation_date: "2024-01-30T17:54:50.706Z".parse().unwrap(),
                    deleted_date: None,
                },
                Cipher {
                    id: "646594a9-a9cb-4082-9d57-0024c3fbcaa9".parse().unwrap(),
                    folder_id: None,

                    name: "My ssh key".to_string(),
                    notes: None,

                    r#type: CipherType::SshKey(Box::new(SshKey {
                        private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACBinNE5chMtCHh3BV0H1+CpPlEQBwR5cD+Xb9i8MaHGiwAAAKAy48fwMuPH\n8AAAAAtzc2gtZWQyNTUxOQAAACBinNE5chMtCHh3BV0H1+CpPlEQBwR5cD+Xb9i8MaHGiw\nAAAEAYUCIdfLI14K3XIy9V0FDZLQoZ9gcjOnvFjb4uA335HmKc0TlyEy0IeHcFXQfX4Kk+\nURAHBHlwP5dv2LwxocaLAAAAHHF1ZXh0ZW5ATWFjQm9vay1Qcm8tMTYubG9jYWwB\n-----END OPENSSH PRIVATE KEY-----".to_string(),
                        public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGKc0TlyEy0IeHcFXQfX4Kk+URAHBHlwP5dv2LwxocaL".to_string(),
                        fingerprint: "SHA256:1JjFjvPRkj1Gbf2qRP1dgHiIzEuNAEvp+92x99jw3K0".to_string(),
                    })),

                    favorite: false,
                    reprompt: 0,

                    fields: vec![],

                    password_history: None,
                    revision_date: "2024-01-30T11:25:25.466Z".parse().unwrap(),
                    creation_date: "2024-01-30T11:25:25.466Z".parse().unwrap(),
                    deleted_date: None,
                }
            ],
        )
        .unwrap();

        assert_eq!(
            export.parse::<serde_json::Value>().unwrap(),
            expected.parse::<serde_json::Value>().unwrap()
        )
    }

    /// Verifies that populated `fido2_credentials` flow through to the JSON export. The web
    /// exporter includes these credentials and we must do the same so iOS/Android JSON exports
    /// don't silently drop passkeys.
    #[test]
    fn test_login_with_fido2_credentials() {
        let cipher = Cipher {
            id: "25c8c414-b446-48e9-a1bd-b10700bbd740".parse().unwrap(),
            folder_id: None,
            name: "Bitwarden".to_string(),
            notes: None,
            r#type: CipherType::Login(Box::new(Login {
                username: None,
                password: None,
                login_uris: vec![],
                totp: None,
                fido2_credentials: Some(vec![Fido2Credential {
                    credential_id: "e8d88789-e916-e196-3cbd-81dafae71bbc".to_string(),
                    key_type: "public-key".to_string(),
                    key_algorithm: "ECDSA".to_string(),
                    key_curve: "P-256".to_string(),
                    key_value: "AAECAwQFBg".to_string(),
                    rp_id: "bitwarden.com".to_string(),
                    user_handle: Some("AAECAwQFBg".to_string()),
                    user_name: Some("user@example.com".to_string()),
                    counter: 0,
                    rp_name: Some("Bitwarden".to_string()),
                    user_display_name: Some("User".to_string()),
                    discoverable: "true".to_string(),
                    creation_date: "2024-06-07T14:12:36.150Z".parse().unwrap(),
                }]),
            })),
            favorite: false,
            reprompt: 0,
            fields: vec![],
            password_history: None,
            revision_date: "2024-01-30T14:09:33.753Z".parse().unwrap(),
            creation_date: "2024-01-30T11:23:54.416Z".parse().unwrap(),
            deleted_date: None,
        };

        let json = serde_json::to_value(JsonCipher::from(cipher)).unwrap();
        let creds = &json["login"]["fido2Credentials"];

        assert_eq!(creds.as_array().unwrap().len(), 1);
        assert_eq!(
            creds[0]["credentialId"],
            "e8d88789-e916-e196-3cbd-81dafae71bbc"
        );
        assert_eq!(creds[0]["keyType"], "public-key");
        // Counter and discoverable are serialized as strings to match the web exporter.
        assert_eq!(creds[0]["counter"], "0");
        assert_eq!(creds[0]["discoverable"], "true");
        // Dates use millisecond precision to match JavaScript's toISOString().
        assert_eq!(creds[0]["creationDate"], "2024-06-07T14:12:36.150Z");
    }

    /// Verifies that populated `password_history` is included in the JSON export. The web
    /// exporter emits these entries and the SDK previously hardcoded them to null.
    #[test]
    fn test_cipher_with_password_history() {
        let cipher = Cipher {
            id: "25c8c414-b446-48e9-a1bd-b10700bbd740".parse().unwrap(),
            folder_id: None,
            name: "Bitwarden".to_string(),
            notes: None,
            r#type: CipherType::Login(Box::new(Login {
                username: None,
                password: None,
                login_uris: vec![],
                totp: None,
                fido2_credentials: None,
            })),
            favorite: false,
            reprompt: 0,
            fields: vec![],
            password_history: Some(vec![PasswordHistory {
                password: "old-password".to_string(),
                last_used_date: "2024-01-30T14:09:33.753Z".parse().unwrap(),
            }]),
            revision_date: "2024-01-30T14:09:33.753Z".parse().unwrap(),
            creation_date: "2024-01-30T11:23:54.416Z".parse().unwrap(),
            deleted_date: None,
        };

        let json = serde_json::to_value(JsonCipher::from(cipher)).unwrap();
        let history = &json["passwordHistory"];

        assert_eq!(history.as_array().unwrap().len(), 1);
        assert_eq!(history[0]["password"], "old-password");
        assert_eq!(history[0]["lastUsedDate"], "2024-01-30T14:09:33.753Z");
    }

    /// Verifies that sub-millisecond timestamp precision is truncated to milliseconds in the
    /// export, matching JavaScript's `Date.toISOString()` output used by the web exporter.
    #[test]
    fn test_dates_use_millisecond_precision() {
        let cipher = Cipher {
            id: "25c8c414-b446-48e9-a1bd-b10700bbd740".parse().unwrap(),
            folder_id: None,
            name: "Bitwarden".to_string(),
            notes: None,
            r#type: CipherType::SecureNote(Box::new(SecureNote {
                r#type: SecureNoteType::Generic,
            })),
            favorite: false,
            reprompt: 0,
            fields: vec![],
            password_history: None,
            // Microsecond precision in the source value should be truncated to ms in the output.
            revision_date: "2024-01-30T14:09:33.753456Z".parse().unwrap(),
            creation_date: "2024-01-30T11:23:54.416789123Z".parse().unwrap(),
            deleted_date: Some("2024-02-01T00:00:00.000000Z".parse().unwrap()),
        };

        let json = serde_json::to_value(JsonCipher::from(cipher)).unwrap();

        assert_eq!(json["revisionDate"], "2024-01-30T14:09:33.753Z");
        assert_eq!(json["creationDate"], "2024-01-30T11:23:54.416Z");
        assert_eq!(json["deletedDate"], "2024-02-01T00:00:00.000Z");
    }
}
