use bitwarden_crypto::{
    generate_versioned_sealable,
    safe::{DataEnvelopeNamespace, SealableData, SealableVersionedData},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{
    field::FieldType,
    linked_id::LinkedIdType,
    login::UriMatchType,
    secure_note::SecureNoteType,
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CipherBlobV1 {
    pub name: String,
    pub notes: Option<String>,
    pub type_data: CipherTypeDataV1,
    pub fields: Option<Vec<FieldDataV1>>,
    pub password_history: Option<Vec<PasswordHistoryDataV1>>,
}

impl SealableData for CipherBlobV1 {}

generate_versioned_sealable!(
    CipherBlob,
    DataEnvelopeNamespace::VaultItem,
    [CipherBlobV1 => "1"]
);

pub(crate) type CipherBlobLatest = CipherBlobV1;

// IdentityDataV1 is significantly larger than other variants (432 bytes vs ~144 bytes).
// Boxing could be considered if this becomes a performance concern, but since these types are
// only constructed during deserialization from encrypted blobs, the stack size is acceptable.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub(crate) enum CipherTypeDataV1 {
    Login(LoginDataV1),
    Card(CardDataV1),
    Identity(IdentityDataV1),
    SecureNote(SecureNoteDataV1),
    SshKey(SshKeyDataV1),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginDataV1 {
    pub username: Option<String>,
    pub password: Option<String>,
    pub password_revision_date: Option<DateTime<Utc>>,
    pub uris: Option<Vec<LoginUriDataV1>>,
    pub totp: Option<String>,
    pub autofill_on_page_load: Option<bool>,
    pub fido2_credentials: Option<Vec<Fido2CredentialDataV1>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginUriDataV1 {
    pub uri: Option<String>,
    pub r#match: Option<UriMatchType>,
    pub uri_checksum: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Fido2CredentialDataV1 {
    pub credential_id: String,
    pub key_type: String,
    pub key_algorithm: String,
    pub key_curve: String,
    pub key_value: String,
    pub rp_id: String,
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub counter: String,
    pub rp_name: Option<String>,
    pub user_display_name: Option<String>,
    pub discoverable: String,
    pub creation_date: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CardDataV1 {
    pub cardholder_name: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IdentityDataV1 {
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SecureNoteDataV1 {
    #[serde(rename = "secureNoteType")]
    pub r#type: SecureNoteType,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SshKeyDataV1 {
    pub private_key: String,
    pub public_key: String,
    pub fingerprint: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FieldDataV1 {
    pub name: Option<String>,
    pub value: Option<String>,
    pub r#type: FieldType,
    pub linked_id: Option<LinkedIdType>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PasswordHistoryDataV1 {
    pub password: String,
    pub last_used_date: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_login_blob() -> CipherBlobV1 {
        CipherBlobV1 {
            name: "Test Login".to_string(),
            notes: Some("Some notes".to_string()),
            type_data: CipherTypeDataV1::Login(LoginDataV1 {
                username: Some("user@example.com".to_string()),
                password: Some("p@ssw0rd".to_string()),
                password_revision_date: Some("2024-01-01T00:00:00Z".parse().unwrap()),
                uris: Some(vec![LoginUriDataV1 {
                    uri: Some("https://example.com".to_string()),
                    r#match: Some(UriMatchType::Domain),
                    uri_checksum: Some("checksum123".to_string()),
                }]),
                totp: Some("otpauth://totp/test".to_string()),
                autofill_on_page_load: Some(true),
                fido2_credentials: Some(vec![Fido2CredentialDataV1 {
                    credential_id: "cred-id".to_string(),
                    key_type: "public-key".to_string(),
                    key_algorithm: "ECDSA".to_string(),
                    key_curve: "P-256".to_string(),
                    key_value: "key-value-data".to_string(),
                    rp_id: "example.com".to_string(),
                    user_handle: Some("user-handle".to_string()),
                    user_name: Some("user@example.com".to_string()),
                    counter: "0".to_string(),
                    rp_name: Some("Example".to_string()),
                    user_display_name: Some("Test User".to_string()),
                    discoverable: "true".to_string(),
                    creation_date: "2024-01-01T00:00:00Z".parse().unwrap(),
                }]),
            }),
            fields: Some(vec![FieldDataV1 {
                name: Some("custom field".to_string()),
                value: Some("custom value".to_string()),
                r#type: FieldType::Text,
                linked_id: None,
            }]),
            password_history: Some(vec![PasswordHistoryDataV1 {
                password: "old-password".to_string(),
                last_used_date: "2024-01-01T00:00:00Z".parse().unwrap(),
            }]),
        }
    }

    #[test]
    fn test_login_serialization_roundtrip() {
        let blob = make_login_blob();
        let json = serde_json::to_string(&blob).unwrap();
        let deserialized: CipherBlobV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(blob, deserialized);
    }

    #[test]
    fn test_card_serialization_roundtrip() {
        let blob = CipherBlobV1 {
            name: "Test Card".to_string(),
            notes: None,
            type_data: CipherTypeDataV1::Card(CardDataV1 {
                cardholder_name: Some("John Doe".to_string()),
                exp_month: Some("12".to_string()),
                exp_year: Some("2025".to_string()),
                code: Some("123".to_string()),
                brand: Some("Visa".to_string()),
                number: Some("4111111111111111".to_string()),
            }),
            fields: None,
            password_history: None,
        };
        let json = serde_json::to_string(&blob).unwrap();
        let deserialized: CipherBlobV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(blob, deserialized);
    }

    #[test]
    fn test_identity_serialization_roundtrip() {
        let blob = CipherBlobV1 {
            name: "Test Identity".to_string(),
            notes: None,
            type_data: CipherTypeDataV1::Identity(IdentityDataV1 {
                title: Some("Mr".to_string()),
                first_name: Some("John".to_string()),
                middle_name: None,
                last_name: Some("Doe".to_string()),
                address1: Some("123 Main St".to_string()),
                address2: None,
                address3: None,
                city: Some("Anytown".to_string()),
                state: Some("CA".to_string()),
                postal_code: Some("12345".to_string()),
                country: Some("US".to_string()),
                company: Some("Acme".to_string()),
                email: Some("john@example.com".to_string()),
                phone: Some("555-1234".to_string()),
                ssn: Some("123-45-6789".to_string()),
                username: Some("johndoe".to_string()),
                passport_number: None,
                license_number: None,
            }),
            fields: None,
            password_history: None,
        };
        let json = serde_json::to_string(&blob).unwrap();
        let deserialized: CipherBlobV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(blob, deserialized);
    }

    #[test]
    fn test_secure_note_serialization_roundtrip() {
        let blob = CipherBlobV1 {
            name: "Test Note".to_string(),
            notes: Some("Secret notes here".to_string()),
            type_data: CipherTypeDataV1::SecureNote(SecureNoteDataV1 {
                r#type: SecureNoteType::Generic,
            }),
            fields: None,
            password_history: None,
        };
        let json = serde_json::to_string(&blob).unwrap();
        let deserialized: CipherBlobV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(blob, deserialized);
    }

    #[test]
    fn test_ssh_key_serialization_roundtrip() {
        let blob = CipherBlobV1 {
            name: "Test SSH Key".to_string(),
            notes: None,
            type_data: CipherTypeDataV1::SshKey(SshKeyDataV1 {
                private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
                public_key: "ssh-ed25519 AAAA...".to_string(),
                fingerprint: "SHA256:abc123".to_string(),
            }),
            fields: None,
            password_history: None,
        };
        let json = serde_json::to_string(&blob).unwrap();
        let deserialized: CipherBlobV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(blob, deserialized);
    }

    #[test]
    fn test_versioned_enum_format() {
        let blob = CipherBlobV1 {
            name: "Test".to_string(),
            notes: None,
            type_data: CipherTypeDataV1::SecureNote(SecureNoteDataV1 {
                r#type: SecureNoteType::Generic,
            }),
            fields: None,
            password_history: None,
        };
        let versioned: CipherBlob = blob.into();
        let json = serde_json::to_value(&versioned).unwrap();

        assert_eq!(json["version"], "1");
        assert!(json["content"].is_object());
        assert_eq!(json["content"]["name"], "Test");
    }

    #[test]
    fn test_from_conversion() {
        let blob = CipherBlobV1 {
            name: "Test".to_string(),
            notes: None,
            type_data: CipherTypeDataV1::SecureNote(SecureNoteDataV1 {
                r#type: SecureNoteType::Generic,
            }),
            fields: None,
            password_history: None,
        };
        let versioned: CipherBlob = blob.clone().into();
        assert_eq!(versioned, CipherBlob::CipherBlobV1(blob));
    }
}
