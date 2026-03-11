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
    use bitwarden_core::key_management::KeyIds;
    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey, safe::DataEnvelope};
    use bitwarden_encoding::B64;

    use super::*;
    use crate::cipher::{blob::CipherBlob, secure_note::SecureNoteType};

    const TEST_VECTOR_CEK: &str =
        "pQEEAlApYxU9rgfIc9v9sHuglhkKAzoAARFvBIEEIFggDKYmieFA7a0UoOMAt4BErOpk7VfwZI8Dk0Yc9FxFzWIB";
    const TEST_VECTOR_ENVELOPE: &str = "g1hLpQE6AAERbwN4I2FwcGxpY2F0aW9uL3guYml0d2FyZGVuLmNib3ItcGFkZGVkBFApYxU9rgfIc9v9sHuglhkKOgABOIECOgABOIABoQVYGMihknYX7mrmC03/w0V7rTMij2+q237p21h2H2Sq0hnlzZ4ka8yMW1yFOOMSt5ZS3tNQxzT07qeeY10tAeczgizA2g5AvmIQJdXK+7KR5mP3zk5VaVfGjC9mZUUFXwIAXsxC16HUII7Z1Iwhpd+MrJDf+itZGFVd07ExaXkH5+MjfaXhJqXBSxAStCG5zLGsEg==";

    fn test_blob() -> CipherBlobV1 {
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

    #[test]
    #[ignore]
    fn generate_test_vectors() {
        let data: CipherBlob = test_blob().into();
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (envelope, cek_id) = DataEnvelope::seal(data, &mut ctx).unwrap();

        #[allow(deprecated)]
        let cek = ctx.dangerous_get_symmetric_key(cek_id).unwrap();
        println!("const TEST_VECTOR_CEK: &str = \"{}\";", cek.to_base64());
        println!(
            "const TEST_VECTOR_ENVELOPE: &str = \"{}\";",
            String::from(envelope)
        );
    }

    #[test]
    fn test_recorded_test_vector() {
        let cek = SymmetricCryptoKey::try_from(B64::try_from(TEST_VECTOR_CEK).unwrap()).unwrap();

        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let cek_id = ctx.add_local_symmetric_key(cek);

        let envelope: DataEnvelope = TEST_VECTOR_ENVELOPE.parse().unwrap();
        let unsealed: CipherBlob = envelope
            .unseal(cek_id, &mut ctx)
            .expect("CipherBlobV1 has changed in a backwards-incompatible way. Existing encrypted data must remain deserializable. If a new format is needed, create a new version instead of modifying V1.");
        assert_eq!(unsealed, test_blob().into());
    }
}
