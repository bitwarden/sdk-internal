use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::cipher::{
    field::FieldType, linked_id::LinkedIdType, login::UriMatchType, secure_note::SecureNoteType,
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CipherBlobV1 {
    pub name: String,
    pub notes: Option<String>,
    pub type_data: CipherTypeDataV1,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FieldDataV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub password_history: Vec<PasswordHistoryDataV1>,
}

impl bitwarden_crypto::safe::SealableData for CipherBlobV1 {}

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
    BankAccount(BankAccountDataV1),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginDataV1 {
    pub username: Option<String>,
    pub password: Option<String>,
    pub password_revision_date: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uris: Vec<LoginUriDataV1>,
    pub totp: Option<String>,
    pub autofill_on_page_load: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fido2_credentials: Vec<Fido2CredentialDataV1>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginUriDataV1 {
    pub uri: Option<String>,
    pub r#match: Option<UriMatchType>,
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
    pub counter: u64,
    pub rp_name: Option<String>,
    pub user_display_name: Option<String>,
    pub discoverable: bool,
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
pub(crate) struct BankAccountDataV1 {
    pub bank_name: Option<String>,
    pub name_on_account: Option<String>,
    pub account_type: Option<String>,
    pub account_number: Option<String>,
    pub routing_number: Option<String>,
    pub branch_number: Option<String>,
    pub pin: Option<String>,
    pub swift_code: Option<String>,
    pub iban: Option<String>,
    pub bank_contact_phone: Option<String>,
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
    use bitwarden_core::key_management::KeySlotIds;
    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey, safe::DataEnvelope};
    use bitwarden_encoding::B64;
    use chrono::TimeZone;

    use super::*;
    use crate::cipher::{
        blob::CipherBlob, linked_id::LoginLinkedIdType, secure_note::SecureNoteType,
    };

    const TEST_VECTOR_SECURE_NOTE_CEK: &str =
        "pQEEAlApYxU9rgfIc9v9sHuglhkKAzoAARFvBIEEIFggDKYmieFA7a0UoOMAt4BErOpk7VfwZI8Dk0Yc9FxFzWIB";
    const TEST_VECTOR_SECURE_NOTE_ENVELOPE: &str = "g1hLpQE6AAERbwN4I2FwcGxpY2F0aW9uL3guYml0d2FyZGVuLmNib3ItcGFkZGVkBFApYxU9rgfIc9v9sHuglhkKOgABOIECOgABOIABoQVYGMihknYX7mrmC03/w0V7rTMij2+q237p21h2H2Sq0hnlzZ4ka8yMW1yFOOMSt5ZS3tNQxzT07qeeY10tAeczgizA2g5AvmIQJdXK+7KR5mP3zk5VaVfGjC9mZUUFXwIAXsxC16HUII7Z1Iwhpd+MrJDf+itZGFVd07ExaXkH5+MjfaXhJqXBSxAStCG5zLGsEg==";

    const TEST_VECTOR_LOGIN_CEK: &str =
        "pQEEAlClJ9tO9x8fN2JVe5N8uzAaAzoAARFvBIEEIFggZwJXkLK7A6Sy5Y9+dacJrzCg9bo4RMRxXaRGDWYfbTYB";
    const TEST_VECTOR_LOGIN_ENVELOPE: &str = "g1hLpQE6AAERbwN4I2FwcGxpY2F0aW9uL3guYml0d2FyZGVuLmNib3ItcGFkZGVkBFClJ9tO9x8fN2JVe5N8uzAaOgABOIECOgABOIABoQVYGNYP1rgAT3D2T6q2lGTRjIPHR2IELUDWE1kC2erlZM4Dqyeew1VlDkdXnZIE+t2g4SJh8IFSHo9WuzmyY+qC+V9cuGW3QHt+sg7pfZ5kQBh40U9uxUcxOHdVF3jQhcAmgB9abShR68u41NMDwwLSafG8PLzsUfhhxpCG0+ZuOda3tFVM1y5TyiDPJBBoJECuYK/K/1RLNAWAy5AU98yI0RgdK0MHxpoOqdSC8dXXu6fGgON7XLQWkkceFWILp0o51/c7OvdJ3B1nCiCIZjwAyS96+oWOzLrsPaGkBjqedBCi5iwelzLOttXk6nrzE/FfC0PkeeSsPSr9UdXBbeuUSK7wKtir9Lx/gtJ4sMPFidtTNdXCcDT9RA7y21h+3+wHQgGSlOGRigXFgXWi5ajSPCs9zLn7ERoG4BZ4IHa6EMSJbGH1pANW+Ibg4aadBF7LzOi/BZx2oZ/6z54XfAfqb44FR3/XXdNFHosPH9IH7CkKbNvLTuGrOTk9S998qFDNkWeGthrDYclaYSFktSHULvmHhSPadRL4uM6254HTmSjTAG6FDhhqdJU3SvoifrvBeHqjEP7F5R+zjVQol+JUcs/ExwmlrxXETOTzGyC/++FflZyPIUnH9U7ZqXhiYGd0ZvcyrnrnieehYToWFdwFR9ho+6h9hB/SCjhGudP5CRPZDL9GkNAUS5+pAd4ZC19fDjWpwMnEbgPTuthXKl6YRHxxCV+xpc9jncVQt9zF31e0bSIP7kVcdmlgjXaV6Nmd3aZ+PqeJnj27gCxG2tZkMimdJmEgxkL/cfvNHENg43+rpnV2mCTrCAO/X+RDGKdi7SIzsLesPVXVHEZCM4UBv2v+S/vpDFC3ie09cz525PCgt/7Je68k8S5WsTwKVeL0+T/ysqDo7wJvFSToY2G/LOGnBYMUYcCLfJGQbD8g2xI3oC+go8kcyVDJv+936/MkAYSxnvZDrMr30zEZaNm5YBh8cRqKr4MxOjJBk1XWjwDNsSQrDw==";

    const TEST_VECTOR_CARD_CEK: &str =
        "pQEEAlBqeNyImi1f1pMtJVlvDuV1AzoAARFvBIEEIFggyyOmMlDBj/oRic4qPjXnnKXGf4QGYMq7KvztZO3it+cB";
    const TEST_VECTOR_CARD_ENVELOPE: &str = "g1hLpQE6AAERbwN4I2FwcGxpY2F0aW9uL3guYml0d2FyZGVuLmNib3ItcGFkZGVkBFBqeNyImi1f1pMtJVlvDuV1OgABOIECOgABOIABoQVYGHZO47yxMBN7r8jgWNJ8c+1bfUld0uzdNli2xQgFm6X0chG+qNdkiROVAUxi75+cN4jiTOzt41pG7bXyo7U4D8R38zR+l7jePi39w3YV4tnmxIenwBPK/0qdO8pLKUMwi8PMIBqJ2UxanLqRhP6Ru2i43rpVZMgAmasGgzGG8hhJttii1CidG8ntNP/zRvRl38F/7bphlN1a08/FeycdIAfQUf7tgzoaj1JegSwEs1M7/+ONHlPtlkmovN/zJTP0ZHL7U7NAt/JBIWbeScbGP6E=";

    const TEST_VECTOR_IDENTITY_CEK: &str =
        "pQEEAlBKyRoZr3LVRJsXJQ1msUhQAzoAARFvBIEEIFggVf/R4MMZFsa5DDtjjTG/1GozhF9jNQACFt9KpMpA9D8B";
    const TEST_VECTOR_IDENTITY_ENVELOPE: &str = "g1hLpQE6AAERbwN4I2FwcGxpY2F0aW9uL3guYml0d2FyZGVuLmNib3ItcGFkZGVkBFBKyRoZr3LVRJsXJQ1msUhQOgABOIECOgABOIABoQVYGNZ9Ckqt+ftCL1eTn3LHTP/bLQVSiT2nFFkBl2ON9MRyKHrBCGlRlKxcGgMhFQhf3LY7kiDTjvvUhbZr3/rbc/fA8+7HS2UYu/SMOnxF4fg5AlBDc2kwE5iPqwJAJU4fnMqlQm+0jBAE2MS7oppPwHYh8cxDE9pqEa7Ehz1XygUgmUWtEpgGo2Nia+mdCnltws2X+uLCeAf6x5Ioc+HvFUIzFiYEN4WQ+NLmaCNrES9Zw9TXQTSh0drdPqaW7SSMjpBLk1TRtKX4hnSqE+tlRcfG24hPf214jG8On9tw1cdMQbF9GeC2FidfX+snjrU5psmje2bCcExfnvL7pgPeTV/R6+Fct0Jx5pKFXdTQM3SM1Ms8I+sq22sSc9Bu++V9nXFlLIyvWF9H/9FMYXrUR6HfBzSMJk7BSSin4wk/BKTEE59uaW+MtT/sDsW76aRo29VUqymbd5aezHCNxM8CFYaRGEXqWmakwXOPkqZh6CRhT3IZ6MjMQw2GbmDG+qv/KcbJatlKT1ZE6LUos/zpErOf0AT16D1WkS+9QwIeTP5QLv6F291nlBR2xDPg9v/cuauw";

    const TEST_VECTOR_SSH_KEY_CEK: &str =
        "pQEEAlApE2RsnNwb3+3FyIr/kcfWAzoAARFvBIEEIFggDk3igU6wYnicl6jRSYILSaPlDWYCjnRUqMLdqfPkVKAB";
    const TEST_VECTOR_SSH_KEY_ENVELOPE: &str = "g1hLpQE6AAERbwN4I2FwcGxpY2F0aW9uL3guYml0d2FyZGVuLmNib3ItcGFkZGVkBFApE2RsnNwb3+3FyIr/kcfWOgABOIECOgABOIABoQVYGHPwqnuSuDHdwTg3twT5B0b3AXKVK+cySVkBSzorjdnfAdt1aNM32x3BPUg4QMkR99SQum3yc4eIT5eqi2FZjHyvEVPMwxfcWqg26g8UTc3dsRW57RYRF4ajx4+MGcJj+wWTrI8jPmthhLAnEHT11eC2YjYIW1INWKGFJTKnTjwHw1LTVJvEzA9MAZRk2y2NC+qkkdDM3wKmhl4PqoEPmt/x6qBjlR5+rlA4rUqkm9ja+NqqEbz8McGXBw8QWOh99/xE1PorFk7S+o9LW1Kcv1/GL+1wv6X7tTo1dYVYa2uCo9Hp9C8D5zXz/iVLm9w98NQFZQlteO8yibEOp+F/VNpgpsmZjOQzJ6wf0hKabFF2eXIUJ2RT1vJT+zUdcfc+TMkypaBbJEagmAiEBnZFcxVEhQ3tn1ZyJFRUcMzm91azIHQMmQ9cS6h/SqTGFF3z+q0H4+8w2S+yl+D5/OVWQHKcSOFvsPA=";

    const TEST_VECTOR_BANK_ACCOUNT_CEK: &str =
        "pQEEAlCz1mvOGP9yRKdx0pA5WbP7AzoAARFvBIEEIFggF30KGp58Duu4VcVvoFJ+Lhw1yEpfQvTUW2dvOP+WMd0B";
    const TEST_VECTOR_BANK_ACCOUNT_ENVELOPE: &str = "g1hLpQE6AAERbwN4I2FwcGxpY2F0aW9uL3guYml0d2FyZGVuLmNib3ItcGFkZGVkBFCz1mvOGP9yRKdx0pA5WbP7OgABOIECOgABOIABoQVYGDbBFtW702QwCdi03+f9Uahq4Xf0bJ8i7VkBQxZB8XgvwLS13sHp8iz3VmTVcWJCyoxp6ycEUNSllpzURnZtfTsm9hkHCM0iFvMAXgDHBamHpI+8cX4sZ1qyjrGx4JDkGL1wDPUKMY7pLIN6alssjgYNl/6ijicWk2uNDneAGVgJdAHmxVKYPKbwYp0e8bLeAjgj6FOSFHaXv1a6TdF82iRCF/r5Uh/Ohx1FEbtRnaCSMJ4tLsf8YC9oq3duarJzSB2aINL9EnGAqqUlJ8cy8lyfkopUxV0OMnRWiHpja4CrEphhNeKKPoFRezsVoDYQ3f7kjryVAQ661gVxsEG3FB03+CcvVsT849QfrDcERxsQoKwy1E9yHaoE2kgWiYTHS+6gCH/gikDw1t4GBBUdjeJhP3bqQJbmM4cgRxWMgyswfFAfZok25kcA15EpHabkczydiPtnG2UW9qfu+bfw";

    fn test_blob_secure_note() -> CipherBlobV1 {
        CipherBlobV1 {
            name: "Test Secure Note".to_string(),
            notes: Some("Some notes".to_string()),
            type_data: CipherTypeDataV1::SecureNote(SecureNoteDataV1 {
                r#type: SecureNoteType::Generic,
            }),
            fields: Vec::new(),
            password_history: Vec::new(),
        }
    }

    fn test_blob_login() -> CipherBlobV1 {
        CipherBlobV1 {
            name: "Test Login".to_string(),
            notes: Some("Login notes".to_string()),
            type_data: CipherTypeDataV1::Login(LoginDataV1 {
                username: Some("testuser@example.com".to_string()),
                password: Some("p@ssw0rd123".to_string()),
                password_revision_date: Some(Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap()),
                uris: vec![LoginUriDataV1 {
                    uri: Some("https://example.com/login".to_string()),
                    r#match: Some(UriMatchType::Domain),
                }],
                totp: Some("otpauth://totp/test?secret=JBSWY3DPEHPK3PXP".to_string()),
                autofill_on_page_load: Some(true),
                fido2_credentials: vec![Fido2CredentialDataV1 {
                    credential_id: "credential-id-123".to_string(),
                    key_type: "public-key".to_string(),
                    key_algorithm: "ECDSA".to_string(),
                    key_curve: "P-256".to_string(),
                    key_value: "key-value-base64".to_string(),
                    rp_id: "example.com".to_string(),
                    user_handle: Some("user-handle-456".to_string()),
                    user_name: Some("testuser".to_string()),
                    counter: 42,
                    rp_name: Some("Example".to_string()),
                    user_display_name: Some("Test User".to_string()),
                    discoverable: true,
                    creation_date: Utc.with_ymd_and_hms(2024, 6, 1, 10, 30, 0).unwrap(),
                }],
            }),
            fields: vec![FieldDataV1 {
                name: Some("Custom Field".to_string()),
                value: Some("custom-value".to_string()),
                r#type: FieldType::Linked,
                linked_id: Some(LinkedIdType::Login(LoginLinkedIdType::Username)),
            }],
            password_history: vec![PasswordHistoryDataV1 {
                password: "old-password-1".to_string(),
                last_used_date: Utc.with_ymd_and_hms(2023, 12, 1, 8, 0, 0).unwrap(),
            }],
        }
    }

    fn test_blob_card() -> CipherBlobV1 {
        CipherBlobV1 {
            name: "Test Card".to_string(),
            notes: Some("Card notes".to_string()),
            type_data: CipherTypeDataV1::Card(CardDataV1 {
                cardholder_name: Some("John Doe".to_string()),
                exp_month: Some("12".to_string()),
                exp_year: Some("2028".to_string()),
                code: Some("123".to_string()),
                brand: Some("Visa".to_string()),
                number: Some("4111111111111111".to_string()),
            }),
            fields: Vec::new(),
            password_history: Vec::new(),
        }
    }

    fn test_blob_identity() -> CipherBlobV1 {
        CipherBlobV1 {
            name: "Test Identity".to_string(),
            notes: Some("Identity notes".to_string()),
            type_data: CipherTypeDataV1::Identity(IdentityDataV1 {
                title: Some("Mr".to_string()),
                first_name: Some("John".to_string()),
                middle_name: Some("Michael".to_string()),
                last_name: Some("Doe".to_string()),
                address1: Some("123 Main St".to_string()),
                address2: Some("Apt 4B".to_string()),
                address3: Some("Building C".to_string()),
                city: Some("New York".to_string()),
                state: Some("NY".to_string()),
                postal_code: Some("10001".to_string()),
                country: Some("US".to_string()),
                company: Some("Acme Corp".to_string()),
                email: Some("john.doe@example.com".to_string()),
                phone: Some("555-0123".to_string()),
                ssn: Some("123-45-6789".to_string()),
                username: Some("johndoe".to_string()),
                passport_number: Some("P12345678".to_string()),
                license_number: Some("DL-987654".to_string()),
            }),
            fields: Vec::new(),
            password_history: Vec::new(),
        }
    }

    fn test_blob_ssh_key() -> CipherBlobV1 {
        CipherBlobV1 {
            name: "Test SSH Key".to_string(),
            notes: Some("SSH key notes".to_string()),
            type_data: CipherTypeDataV1::SshKey(SshKeyDataV1 {
                private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----".to_string(),
                public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test@example.com".to_string(),
                fingerprint: "SHA256:abcdefghijklmnopqrstuvwxyz012345678901234567".to_string(),
            }),
            fields: Vec::new(),
            password_history: Vec::new(),
        }
    }

    fn test_blob_bank_account() -> CipherBlobV1 {
        CipherBlobV1 {
            name: "Test Bank Account".to_string(),
            notes: Some("Bank account notes".to_string()),
            type_data: CipherTypeDataV1::BankAccount(BankAccountDataV1 {
                bank_name: Some("Test Bank".to_string()),
                name_on_account: Some("John Doe".to_string()),
                account_type: Some("Checking".to_string()),
                account_number: Some("1234567890".to_string()),
                routing_number: Some("021000021".to_string()),
                branch_number: Some("001".to_string()),
                pin: Some("1234".to_string()),
                swift_code: Some("TESTUS33".to_string()),
                iban: Some("US12345678901234567890".to_string()),
                bank_contact_phone: Some("555-0123".to_string()),
            }),
            fields: Vec::new(),
            password_history: Vec::new(),
        }
    }

    #[test]
    #[ignore]
    fn generate_test_vectors() {
        let blobs: Vec<(&str, CipherBlobV1)> = vec![
            ("LOGIN", test_blob_login()),
            ("CARD", test_blob_card()),
            ("IDENTITY", test_blob_identity()),
            ("SECURE_NOTE", test_blob_secure_note()),
            ("SSH_KEY", test_blob_ssh_key()),
            ("BANK_ACCOUNT", test_blob_bank_account()),
        ];

        for (name, blob) in blobs {
            let data: CipherBlob = blob.into();
            let store: KeyStore<KeySlotIds> = KeyStore::default();
            let mut ctx = store.context_mut();
            let (envelope, cek_id) = DataEnvelope::seal(data, &mut ctx).unwrap();

            #[allow(deprecated)]
            let cek = ctx.dangerous_get_symmetric_key(cek_id).unwrap();
            println!(
                "const TEST_VECTOR_{}_CEK: &str = \"{}\";",
                name,
                cek.to_base64()
            );
            println!(
                "const TEST_VECTOR_{}_ENVELOPE: &str = \"{}\";",
                name,
                String::from(envelope)
            );
            println!();
        }
    }

    fn verify_test_vector(cek_str: &str, envelope_str: &str, expected: CipherBlobV1) {
        let cek = SymmetricCryptoKey::try_from(B64::try_from(cek_str).unwrap()).unwrap();

        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let cek_id = ctx.add_local_symmetric_key(cek);

        let envelope: DataEnvelope = envelope_str.parse().unwrap();
        let unsealed: CipherBlob = envelope
            .unseal(cek_id, &mut ctx)
            .expect("CipherBlobV1 has changed in a backwards-incompatible way. Existing encrypted data must remain deserializable. If a new format is needed, create a new version instead of modifying V1.");
        assert_eq!(unsealed, expected.into());
    }

    #[test]
    fn test_recorded_secure_note_test_vector() {
        verify_test_vector(
            TEST_VECTOR_SECURE_NOTE_CEK,
            TEST_VECTOR_SECURE_NOTE_ENVELOPE,
            test_blob_secure_note(),
        );
    }

    #[test]
    fn test_recorded_login_test_vector() {
        verify_test_vector(
            TEST_VECTOR_LOGIN_CEK,
            TEST_VECTOR_LOGIN_ENVELOPE,
            test_blob_login(),
        );
    }

    #[test]
    fn test_recorded_card_test_vector() {
        verify_test_vector(
            TEST_VECTOR_CARD_CEK,
            TEST_VECTOR_CARD_ENVELOPE,
            test_blob_card(),
        );
    }

    #[test]
    fn test_recorded_identity_test_vector() {
        verify_test_vector(
            TEST_VECTOR_IDENTITY_CEK,
            TEST_VECTOR_IDENTITY_ENVELOPE,
            test_blob_identity(),
        );
    }

    #[test]
    fn test_recorded_ssh_key_test_vector() {
        verify_test_vector(
            TEST_VECTOR_SSH_KEY_CEK,
            TEST_VECTOR_SSH_KEY_ENVELOPE,
            test_blob_ssh_key(),
        );
    }

    #[test]
    fn test_recorded_bank_account_test_vector() {
        verify_test_vector(
            TEST_VECTOR_BANK_ACCOUNT_CEK,
            TEST_VECTOR_BANK_ACCOUNT_ENVELOPE,
            test_blob_bank_account(),
        );
    }
}
