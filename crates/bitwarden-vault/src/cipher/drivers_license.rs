use bitwarden_api_api::models::CipherDriversLicenseModel;
use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, Decryptable, EncString, KeyStoreContext,
    PrimitiveEncryptable,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use super::cipher::CipherKind;
use crate::{Cipher, VaultParseError, cipher::cipher::CopyableCipherFields};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct DriversLicense {
    pub first_name: Option<EncString>,
    pub middle_name: Option<EncString>,
    pub last_name: Option<EncString>,
    pub date_of_birth: Option<EncString>,
    pub license_number: Option<EncString>,
    pub issuing_country: Option<EncString>,
    pub issuing_state: Option<EncString>,
    pub issue_date: Option<EncString>,
    pub expiration_date: Option<EncString>,
    pub issuing_authority: Option<EncString>,
    pub license_class: Option<EncString>,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct DriversLicenseView {
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

impl CompositeEncryptable<KeySlotIds, SymmetricKeySlotId, DriversLicense> for DriversLicenseView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<DriversLicense, CryptoError> {
        Ok(DriversLicense {
            first_name: self.first_name.encrypt(ctx, key)?,
            middle_name: self.middle_name.encrypt(ctx, key)?,
            last_name: self.last_name.encrypt(ctx, key)?,
            date_of_birth: self.date_of_birth.encrypt(ctx, key)?,
            license_number: self.license_number.encrypt(ctx, key)?,
            issuing_country: self.issuing_country.encrypt(ctx, key)?,
            issuing_state: self.issuing_state.encrypt(ctx, key)?,
            issue_date: self.issue_date.encrypt(ctx, key)?,
            expiration_date: self.expiration_date.encrypt(ctx, key)?,
            issuing_authority: self.issuing_authority.encrypt(ctx, key)?,
            license_class: self.license_class.encrypt(ctx, key)?,
        })
    }
}

impl Decryptable<KeySlotIds, SymmetricKeySlotId, DriversLicenseView> for DriversLicense {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<DriversLicenseView, CryptoError> {
        Ok(DriversLicenseView {
            first_name: self.first_name.decrypt(ctx, key).ok().flatten(),
            middle_name: self.middle_name.decrypt(ctx, key).ok().flatten(),
            last_name: self.last_name.decrypt(ctx, key).ok().flatten(),
            date_of_birth: self.date_of_birth.decrypt(ctx, key).ok().flatten(),
            license_number: self.license_number.decrypt(ctx, key).ok().flatten(),
            issuing_country: self.issuing_country.decrypt(ctx, key).ok().flatten(),
            issuing_state: self.issuing_state.decrypt(ctx, key).ok().flatten(),
            issue_date: self.issue_date.decrypt(ctx, key).ok().flatten(),
            expiration_date: self.expiration_date.decrypt(ctx, key).ok().flatten(),
            issuing_authority: self.issuing_authority.decrypt(ctx, key).ok().flatten(),
            license_class: self.license_class.decrypt(ctx, key).ok().flatten(),
        })
    }
}

impl CipherKind for DriversLicense {
    fn decrypt_subtitle(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<String, CryptoError> {
        let first_name: Option<String> = self
            .first_name
            .as_ref()
            .map(|f| f.decrypt(ctx, key))
            .transpose()?;
        let last_name: Option<String> = self
            .last_name
            .as_ref()
            .map(|l| l.decrypt(ctx, key))
            .transpose()?;
        let parts: Vec<String> = [first_name, last_name]
            .into_iter()
            .flatten()
            .filter(|s| !s.is_empty())
            .collect();
        Ok(parts.join(" "))
    }

    fn get_copyable_fields(&self, _: Option<&Cipher>) -> Vec<CopyableCipherFields> {
        [self
            .license_number
            .as_ref()
            .map(|_| CopyableCipherFields::DriversLicenseLicenseNumber)]
        .into_iter()
        .flatten()
        .collect()
    }
}

impl TryFrom<CipherDriversLicenseModel> for DriversLicense {
    type Error = VaultParseError;

    fn try_from(dl: CipherDriversLicenseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            first_name: EncString::try_from_optional(dl.first_name)?,
            middle_name: EncString::try_from_optional(dl.middle_name)?,
            last_name: EncString::try_from_optional(dl.last_name)?,
            date_of_birth: EncString::try_from_optional(dl.date_of_birth)?,
            license_number: EncString::try_from_optional(dl.license_number)?,
            issuing_country: EncString::try_from_optional(dl.issuing_country)?,
            issuing_state: EncString::try_from_optional(dl.issuing_state)?,
            issue_date: EncString::try_from_optional(dl.issue_date)?,
            expiration_date: EncString::try_from_optional(dl.expiration_date)?,
            issuing_authority: EncString::try_from_optional(dl.issuing_authority)?,
            license_class: EncString::try_from_optional(dl.license_class)?,
        })
    }
}

impl From<DriversLicense> for CipherDriversLicenseModel {
    fn from(dl: DriversLicense) -> Self {
        Self {
            first_name: dl.first_name.map(|n| n.to_string()),
            middle_name: dl.middle_name.map(|n| n.to_string()),
            last_name: dl.last_name.map(|n| n.to_string()),
            date_of_birth: dl.date_of_birth.map(|n| n.to_string()),
            license_number: dl.license_number.map(|n| n.to_string()),
            issuing_country: dl.issuing_country.map(|n| n.to_string()),
            issuing_state: dl.issuing_state.map(|n| n.to_string()),
            issue_date: dl.issue_date.map(|n| n.to_string()),
            expiration_date: dl.expiration_date.map(|n| n.to_string()),
            issuing_authority: dl.issuing_authority.map(|n| n.to_string()),
            license_class: dl.license_class.map(|n| n.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::create_test_crypto_with_user_key;
    use bitwarden_crypto::SymmetricCryptoKey;

    use super::*;
    use crate::cipher::cipher::CopyableCipherFields;

    const TEST_VECTOR_DL_KEY: &str =
        "taqu8EG0R01PCl/p0mM8q2Pz3OmCcw66AEoXF82dwhsIUgSR7Fw7yZNXkjtWNC3qxtjkKsFn8xMg1zwUQplD3Q==";
    const TEST_VECTOR_DL_JSON: &str = r#"{"firstName":"2.knZfEnxppJSnCv2K1JLJZQ==|WdifZ8QIUkFuSeVk8WBlSQ==|OX4LNsv+l0Z2EhqNWMgemTZgMwLs5o8T6Osra9nzmU4=","middleName":"2.QrbWBvz1v1139ab0PXCE0g==|qjpNmAzfm5thbkfsb+inmA==|FVmBwCVB+VCKPGKSTLqBCpQWfYeomO/9K4M80i4Hz74=","lastName":"2.kLvD+H8AvuZ26sZSVXCwJw==|hOpCZQ1pSmRxU+10Mb6itg==|890LMSpvyTPumcaBZV2Q/sa0aU0xWSxHGn6Oz/aUvcY=","dateOfBirth":"2.tz5PMtlTQlGiyhrmtFpkfQ==|q7aKh0RO/3UpuzxkWJj/lw==|W+dL85zWGf6hmZby1rkekwFSiAe3Nlf8JcQ/r8aRvC8=","licenseNumber":"2.tqNWH0mhqCqVkGuylbGJPQ==|d60Z0GfOZrQdnDDRSQSYig==|bVQ9kEO13+pGFr5CnA2AcsXHlKdntsB7dWXxu9dPViQ=","issuingCountry":"2.4c/os2TnGc4lV48zTXtcrA==|48WLHeewxx53cR0oAJrT9Q==|DbdhHEl+ZjFJsAwCJqdx6smENOJ6aa6prOSSzrIaxsw=","issuingState":"2.sXVmW8/M1Dt9of6UR8bOFQ==|Se5KFBLQ0EiUywa3Hll6eg==|pIfsxpZrXh1Z3+VG2HX2sXpQfJ1GrlFq8DyunOr/vk0=","issueDate":"2.NiEamcsCLptp7ZGR5yv+Kw==|iS0jlJFbscygj+8q/E3FWA==|M0Iq6DqgDTI3l/OArBeqtdR4dHXLi87QexEK1H7XwsE=","expirationDate":"2.oEePzQ/7a8bC8y93Wf1cog==|QtbxhibvRGdBctqETfYqgQ==|zQflEdAhXKxZelF7qLbAdJNqhZXG0v331XwdGEzr10Q=","issuingAuthority":"2.prE7jFCIfr0+DU0XnOSXWw==|fyISTE3sQFp1GnmVpaTRGg==|a+i1vTOoPtj0bkvFjRUXdXxkVq2RtOkv6zuMxS+BOQc=","licenseClass":"2.Yk070ToPNCnbxxQ2CPe20w==|4eb1WaAOXenbQcotMhgaCw==|yGkq0dg6b65Nf6WxbOPV/r7MRDKFplcWLQ7sZNmOlCY="}"#;

    fn test_drivers_license_view() -> DriversLicenseView {
        DriversLicenseView {
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
        }
    }

    #[test]
    #[ignore]
    fn generate_test_vector() {
        let key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let key_b64 = key.to_base64();
        let key_store = create_test_crypto_with_user_key(key);
        let key_slot = SymmetricKeySlotId::User;
        let mut ctx = key_store.context();

        let encrypted = test_drivers_license_view()
            .encrypt_composite(&mut ctx, key_slot)
            .unwrap();
        let json = serde_json::to_string(&encrypted).unwrap();

        println!("const TEST_VECTOR_DL_KEY: &str = \"{key_b64}\";");
        println!("const TEST_VECTOR_DL_JSON: &str = r#\"{json}\"#;");
    }

    #[test]
    fn test_recorded_drivers_license_test_vector() {
        let key =
            SymmetricCryptoKey::try_from(TEST_VECTOR_DL_KEY.to_string()).expect("valid test key");
        let key_store = create_test_crypto_with_user_key(key);
        let key_slot = SymmetricKeySlotId::User;
        let mut ctx = key_store.context();

        let encrypted: DriversLicense =
            serde_json::from_str(TEST_VECTOR_DL_JSON).expect("valid test vector JSON");
        let decrypted: DriversLicenseView = encrypted
            .decrypt(&mut ctx, key_slot)
            .expect("DriversLicense has changed in a backwards-incompatible way. Existing encrypted data must remain decryptable. If a new format is needed, create a new version instead of modifying the existing one.");

        assert_eq!(decrypted, test_drivers_license_view());
    }

    #[test]
    fn test_subtitle_drivers_license() {
        let key = SymmetricCryptoKey::try_from("hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw==".to_string()).unwrap();
        let key_store = create_test_crypto_with_user_key(key);
        let key = SymmetricKeySlotId::User;
        let mut ctx = key_store.context();

        let first_name_encrypted = "John".to_owned().encrypt(&mut ctx, key).unwrap();
        let last_name_encrypted = "Doe".to_owned().encrypt(&mut ctx, key).unwrap();

        let dl = DriversLicense {
            first_name: Some(first_name_encrypted),
            middle_name: None,
            last_name: Some(last_name_encrypted),
            date_of_birth: None,
            license_number: None,
            issuing_country: None,
            issuing_state: None,
            issue_date: None,
            expiration_date: None,
            issuing_authority: None,
            license_class: None,
        };

        assert_eq!(
            dl.decrypt_subtitle(&mut ctx, key).unwrap(),
            "John Doe".to_string()
        );
    }

    #[test]
    fn test_get_copyable_fields_drivers_license() {
        let enc_str: EncString = "2.tMIugb6zQOL+EuOizna1wQ==|W5dDLoNJtajN68yeOjrr6w==|qS4hwJB0B0gNLI0o+jxn+sKMBmvtVgJCRYNEXBZoGeE=".parse().unwrap();

        let dl = DriversLicense {
            first_name: Some(enc_str.clone()),
            middle_name: Some(enc_str.clone()),
            last_name: Some(enc_str.clone()),
            date_of_birth: Some(enc_str.clone()),
            license_number: Some(enc_str.clone()),
            issuing_country: Some(enc_str.clone()),
            issuing_state: Some(enc_str.clone()),
            issue_date: Some(enc_str.clone()),
            expiration_date: Some(enc_str.clone()),
            issuing_authority: Some(enc_str.clone()),
            license_class: Some(enc_str),
        };

        let copyable_fields = dl.get_copyable_fields(None);
        assert_eq!(
            copyable_fields,
            vec![CopyableCipherFields::DriversLicenseLicenseNumber,]
        );
    }
}
