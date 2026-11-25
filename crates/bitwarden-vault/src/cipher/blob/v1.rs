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
    Passport(PassportDataV1),
    DriversLicense(DriversLicenseDataV1),
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
    /// Defaults to `false` for blobs sealed before the setting existed.
    #[serde(default)]
    pub http_authentication_enabled: bool,
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
pub(crate) struct PassportDataV1 {
    pub surname: Option<String>,
    pub given_name: Option<String>,
    pub date_of_birth: Option<String>,
    pub sex: Option<String>,
    pub birth_place: Option<String>,
    pub nationality: Option<String>,
    pub issuing_country: Option<String>,
    pub passport_number: Option<String>,
    pub passport_type: Option<String>,
    pub national_identification_number: Option<String>,
    pub issuing_authority: Option<String>,
    pub issue_date: Option<String>,
    pub expiration_date: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DriversLicenseDataV1 {
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub date_of_birth: Option<String>,
    pub license_number: Option<String>,
    pub issuing_country: Option<String>,
    pub issuing_state: Option<String>,
    pub issue_date: Option<String>,
    pub expiration_date: Option<String>,
    pub issuing_authority: Option<String>,
    pub license_class: Option<String>,
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
        "pQEEAlCaokgVSxN9/91ldE8dxO6XAwMEgQQgWCDewhgXk6Aa3zs1Z/sEWOamUZNd6gUAnw1LLv5Y9zfewAQEBAQ=";
    const TEST_VECTOR_SECURE_NOTE_ENVELOPE: &str = "g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUJqiSBVLE33/3WV0Tx3E7pc6AAE4gQI6AAE4gAGhBUz7JektkAWXSeN3039YdmbFif4KFhV4rp2Y+bo965vKZ5hf7DP7BYUGJsygeRN0e30k0JYiYcrQoLusbdqV/mM4KYvxvmsaHUoxTOkjcIvIWHZDsrZTiykwPKDuwhM/0YOv1j5hodQAN1l3s47clSMoRZj7o1y9133O3ew3R4gJPUivgZU=";

    const TEST_VECTOR_LOGIN_CEK: &str =
        "pQEEAlAPiJuk0g1gP+wJaLiQu5I8AwMEgQQgWCAj4jncSOTYNONjGNiV6dS5cI0dHd2CT+WZd+U4Ico24wQEBAQ=";
    const TEST_VECTOR_LOGIN_ENVELOPE: &str = "g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUA+Im6TSDWA/7AlouJC7kjw6AAE4gQI6AAE4gAGhBUz9wJ+LiuSbPq/KWCdZAvXL/naP/T1Nwq6W5PifCb3wLwRX9GG3+q1E6LyKy4CXFUPTqo6H8zprGTa37Zi+Jim3/B2VUSwU2TWx/tks4w5uSD8kMlGFst3FDp6Z5kIYJqhdU/QTZ+7a7AqSPknMjCqvyQ5uOP+MfXm2K8atZrrudZExbprYD028P0zaJlSZYyshziyZvZ0PRNu3JI/4gAd+HmCL9/xCiraq+d43CSo8JLhcD5OY+2BB3wrjwLGGcmPrSMfMN4/OvYWZhm03bJUli3tLhJ9Q8GWydCyukg2pw7DuQu0BAAM6tMAOOfuRXw/X2cKoH9TWBlstsb8l9ILKJBqWQzn9dIWlphyCq/7bBsUyk9W828e6B7uYJIpkdTXRqmmyWdvgtZXFoDDYnoVBskngsefHtkI4G0CFSnNPO6T69aJHSSDAxwHGZpkoXXA8AYl5WmDcLmj9luODqEnc9GcqPvwHIPG5g8pkWZvO171yJKtj4tiSgjwOYa5b52XePsP6HZvu92Tx2Ttz50ic+NXvvLIhzRb9dGdUaiJtqK+apBl4DYyyU/2BMcDN5YTqCh3C3/dy8LXua52uMy6A8OkGpB/3vWtdIUYgkj7+AJ6iVTTW5fcveG7xk56icr0iBMf66W1EnHXov2/ElzumXoTWJSOl0+kr0FnxLv3JlhJ3cm3k5qQSIpYX19cUyMh+yGAvQ7bmemailRXEeXUbFSFQF78oWciqVOrLtIREaOMK27lM+jcWm9btjsIRxLuyFD5EJBoTgOlA+kZMn4pFWz2AEywVloyeXTBzNSnuUF7CiXorG5V3XGm9sPubbibQkqjMt4y0oFtngqHXKnKfvSUZ5+o6lhYOGYNK2TiBIJgAXMB8Sfo1J/45zWtKSKWsa2mdKGQ9tm8Kr+O/8I0zegdrWyUS7kYwDzKJj1TGxRQLVLwgzNYCK+oXvmpkC2KIQ/lPg+/zMVW7w9WpycDiC5EacgEedlXdSA5dtiA2RlHnBrK764JJ1PPAGFtUn3lwbsae";

    const TEST_VECTOR_CARD_CEK: &str =
        "pQEEAlCOneAvUpRs1bkY1G9d0HxpAwMEgQQgWCD9DYLYWqJdpI8czBpGAOv6kXC9q1se0Er1YsR/1QGADgQEBAQ=";
    const TEST_VECTOR_CARD_ENVELOPE: &str = "g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUI6d4C9SlGzVuRjUb13QfGk6AAE4gQI6AAE4gAGhBUwA8OpzwwkmV3h49A5YtnbGJfwOcro4wPy7oz94jSe3lOzZ8HWApuTBdb+bbMWgE41aFA4dIOpK75sJ6tyOfSjne2hXbaFodCiV0NQTFaySxTmlvGy5jkM1V4QNRb3oqZpjHS3OQKofYPMPF9Ej/5ZiDLtMbg3dr2fDGv6lp88/eWbVk99axYsu5ha2tBnAF7/oOMH7kL13ZeQKTQDhDs3eD/4WQmO0QkhSjqzYY+/YOQYqhlU5kXkgEC5fyEXC2T99lcTZ";

    const TEST_VECTOR_IDENTITY_CEK: &str =
        "pQEEAlAMZd6ap8zi/tpJkrHNH8XYAwMEgQQgWCBkTwn0OLhmIkJo1OOX5oASqjxdJHJyKkgVvq04Kmm4/QQEBAQ=";
    const TEST_VECTOR_IDENTITY_ENVELOPE: &str = "g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUAxl3pqnzOL+2kmSsc0fxdg6AAE4gQI6AAE4gAGhBUx20m3PMk2HXJqRp8RZAZcwDPowg8xsr9fSA6TTgc/GQeOtPQDxRAoBPySS2ynlUIiXSn61JiwwVmPhx14jxXcSEm9CFkv2iAvc67ucwBWfv8hCG0j+piB1rYEuJe10V8Vb4U3x55HKSN/xI+Psqx5WL9iJNOLmTe+WxrHQLKMoapAdoEZ8lTGAX6x9zIY3niJ7Ct77yL5JycFkpdrXPcCxsBdw6zxxQwsx4RKz33CmCl9GKOMm8MiefWWOfyy1PD0U2M2+rnCDxcQ5Dk4rR8A+xQbHC5fAVkLtuYxYE0fdHwW+WQh6rMtOTAFz/0Gi66mb3RHhXgsj8UkA/reu+frAAPDsV+zNkcQg2Ff07iQPYRMbZH/mAaIUE00IwhhacaiRlyrRzcR/lXdx0rABOBdR36XgowFQql9cHRgRJC7FpGgRr0vyh81DHLC4q3mtHMykGCkeSi1Gn7c5kAKiss8gAdPlULVQf2l8GpDwtZK4y813h87DQasND/3XlDMLiZlf39B3f22VdEU9VGYKYXguDQxThPUvCBQ2NWC9FnVvjGZ39aR6Gw==";

    const TEST_VECTOR_SSH_KEY_CEK: &str =
        "pQEEAlBqlZpO8adnuQ/yGgGMfkzFAwMEgQQgWCD55+AbYHk2ymJGpP0aMwzUVGg2Yt6ZJuPA5o4aLWexrAQEBAQ=";
    const TEST_VECTOR_SSH_KEY_ENVELOPE: &str = "g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUGqVmk7xp2e5D/IaAYx+TMU6AAE4gQI6AAE4gAGhBUwJ4TzekCspCMVPjshZAUtpSZuvn2qgDLC1A0ZWiO4cxKJ/I1Xo1dMeqXpMPwBtXmV/wiOe9korAocRWsDM52BwEHJEXQa1hOi70IlD6y4awMjUgjoNNtRqgr4MHRjcs/muGA7OL6GDiZZJMBM7coRY21jtIDu8Iedcf0ExsrSAWJ0KcNAZCRzs99fAY9F2bBBZfxdKulRL9sfVp+ClgWjXTpPHyX1Rj22G+IiA4a+mL6H8Ofv898HTUH8ia7jyoloT/1ZiQZk5Ma1OLz/viy8HIgbF5G66bJTCDoggDZyW27x8Uz1NKAsxXh0XbwRCGXTZqTyE6O4jP6lEaDj/K9kVxsYXAY4GzlfIiL3Ui3WzPDHxNhJ0vBZne1lL8/XMeDM1PDWrnx8iqSW7W/Nj54QZ5aBeTehoOLziNH7gkNH3VUp1gsGyFwmwTq399GqeP5uFEfv8I3LXP4wW";

    const TEST_VECTOR_BANK_ACCOUNT_CEK: &str =
        "pQEEAlBRIdXqvrNOfkzeLHxjudmcAwMEgQQgWCDIEqq6E9Dq35sIu0/PTsgNL2eeXWx8bpYKF0/vwkCrnAQEBAQ=";
    const TEST_VECTOR_BANK_ACCOUNT_ENVELOPE: &str = "g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUFEh1eq+s05+TN4sfGO52Zw6AAE4gQI6AAE4gAGhBUw1W01pp8/7T74igmFZAUPOFKq8Oa0lA6sBTD+HzsbHfCs34ObvbS2wdRKTE/byFr0XUUe52I2K5woob2a88V3uo+Z5RUGoMAoMDa112jTE9G0STkHW/a2NQcf+MymjDYJpXcvk1apUWGHoaP3zMEwpn66TruyhygeNKi+/9NEzAcGw4aFdihsuFkwnv/BcHu1taA3QrmApluvlm0Nz5HFA/AZ+7Xsji1cavU1z5SwFE4oYhr5WNWrd1iq6Jobse+stYIPqvglAlbBxVMviFtF69I8KjUAzlrncirxlPTYpdnjlACcKYNKpUQKDd2HR7/V1/LLN+loyd7Zf5RYnmxjhhYITRPC29mzWKmclKR8gqMA0owUi3JZUV3AAXOEeHuvwLQDyq5LAltWYg5rL7Qnh9UrvUAmIKQw03UTI/GAsW4CZ8QjotHnu/YnKP0n9npUCPw==";

    const TEST_VECTOR_PASSPORT_CEK: &str =
        "pQEEAlAdd8yJ1rFEAWuksaEb7KB9AwMEgQQgWCC4bMyBmuJbMrswZCSjLRdwkadM2KpUPyuxV4BAWi0RkAQEBAQ=";
    const TEST_VECTOR_PASSPORT_ENVELOPE: &str = "g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUB13zInWsUQBa6SxoRvsoH06AAE4gQI6AAE4gAGhBUyuATHGH/+PUzxQ1PBZAX7OOV2WTlm8knramEjS2jv3JtN0XcvlWEODa69gMimmlHN/ar3BRiMsa1aE5Fgp7utumJAWmgoSry5hhuxC6s3XuBcjmnJp1cVDvDT641b/JXGXKrLCMg6Bam9J4g1q+cvhVJwI7I6ysHBWlBp0Ej/iX8ePx1zgiADvswvdy6zDPTODk6qAJ+3mZyWdKs7OzNexPUz7TJtrBgCuPxduCsfLiTHAQARV9KEF9Z/KHflEYN3Kmvp6iFqbNFp5DhC/9auESP03Hsdnmf6lYBJWIA5Hzmntmw3YUvQzvCImT8vXDqpI1KeWK+1L1kuZhIWSq8/iCssAtn2S+WIS0frIKXlkblbHv7BDDfcz88dZH4Ev5sr3kAQuoeV3ec352g4ewhRLOD+1fXaCsQtyPF/SvqOLjZYxWfW0qcBJ5MK2XeuMoVGLYguvZ+S9Xr++vG7hjGMbu/Ztia+56NoaCDNkBE/E+Uv0t8C/3f0biGgDOH+WZZvw3+KiTRNwjcPL28qc";

    const TEST_VECTOR_DRIVERS_LICENSE_CEK: &str =
        "pQEEAlAh7X5+MDiYrWLAVtBecSZDAwMEgQQgWCAFjJ1GLG3Vc0lzbpWcZfPTG9/ukLIAet+2fHkMr8MvAAQEBAQ=";
    const TEST_VECTOR_DRIVERS_LICENSE_ENVELOPE: &str = "g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUCHtfn4wOJitYsBW0F5xJkM6AAE4gQI6AAE4gAGhBUzpEmg3TfBSO0qSElFZAVFcHN2SAyu3qBqVEwtz7oYZEfhB34ZWFkZEbgXSwDqsoAXsEiSRi3BCJhZlLppI9UMFkRFQ1OtGCA4rjFsE6wdxjXDhJYbX+PMuP878Y42mZlvJBUfEPd06Loi5ZUos4XdZ3NKdmBSJTyvsPE4GvA+pes5d0iN6SK5vRd/t42wHEriEvPpcAPsbFPV6p94B+278sGk4KGv6tEz5pnCx1D3wjTmwMCfQXdhqyaQI+K6Sm3W+3PT3HR4OwgBuxrr1snpDOpPcrd+jwowlyvYV+Jug2ajl31gYWPq2IGF9MMikVly7e34d5U6RIGUI3QtVOcjp3B8T4IcifctbSA4kSaqRFxi6q7QKxN5HOFu6wcGe4e+c+VQIbbUWV4i6c5AE4l3zYZJARpWO3sHoVxcecKlVQe62TZ96avZGyWhr+ieIedrglPId8aiky9pUfcUSHqdx";

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
                http_authentication_enabled: false,
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

    fn test_blob_passport() -> CipherBlobV1 {
        CipherBlobV1 {
            name: "Test Passport".to_string(),
            notes: Some("Passport notes".to_string()),
            type_data: CipherTypeDataV1::Passport(PassportDataV1 {
                surname: Some("Doe".to_string()),
                given_name: Some("Jane".to_string()),
                date_of_birth: Some("1990-01-01".to_string()),
                sex: Some("F".to_string()),
                birth_place: Some("New York".to_string()),
                nationality: Some("American".to_string()),
                issuing_country: Some("US".to_string()),
                passport_number: Some("P12345678".to_string()),
                passport_type: Some("P".to_string()),
                national_identification_number: Some("123-45-6789".to_string()),
                issuing_authority: Some("US State Department".to_string()),
                issue_date: Some("2020-01-01".to_string()),
                expiration_date: Some("2030-01-01".to_string()),
            }),
            fields: Vec::new(),
            password_history: Vec::new(),
        }
    }

    fn test_blob_drivers_license() -> CipherBlobV1 {
        CipherBlobV1 {
            name: "Test Driver's License".to_string(),
            notes: Some("Driver's license notes".to_string()),
            type_data: CipherTypeDataV1::DriversLicense(DriversLicenseDataV1 {
                first_name: Some("John".to_string()),
                middle_name: Some("Michael".to_string()),
                last_name: Some("Doe".to_string()),
                date_of_birth: Some("1985-06-15".to_string()),
                license_number: Some("DL-987654".to_string()),
                issuing_country: Some("US".to_string()),
                issuing_state: Some("NY".to_string()),
                issue_date: Some("2020-01-01".to_string()),
                expiration_date: Some("2028-01-01".to_string()),
                issuing_authority: Some("NY DMV".to_string()),
                license_class: Some("D".to_string()),
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
            ("DRIVERS_LICENSE", test_blob_drivers_license()),
            ("PASSPORT", test_blob_passport()),
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

    #[test]
    fn test_recorded_passport_test_vector() {
        verify_test_vector(
            TEST_VECTOR_PASSPORT_CEK,
            TEST_VECTOR_PASSPORT_ENVELOPE,
            test_blob_passport(),
        );
    }

    #[test]
    fn test_recorded_drivers_license_test_vector() {
        verify_test_vector(
            TEST_VECTOR_DRIVERS_LICENSE_CEK,
            TEST_VECTOR_DRIVERS_LICENSE_ENVELOPE,
            test_blob_drivers_license(),
        );
    }

    #[test]
    fn test_login_data_without_http_authentication_enabled_defaults_to_off() {
        let login_data: LoginDataV1 = serde_json::from_value(serde_json::json!({
            "username": "alice@example.com",
            "password": null,
            "passwordRevisionDate": null,
            "totp": null,
            "autofillOnPageLoad": null,
        }))
        .unwrap();

        assert!(!login_data.http_authentication_enabled);
    }
}
