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
