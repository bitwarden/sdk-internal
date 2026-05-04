use bitwarden_api_api::models::CipherPassportModel;
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
pub struct Passport {
    pub surname: Option<EncString>,
    pub given_name: Option<EncString>,
    pub date_of_birth: Option<EncString>,
    pub sex: Option<EncString>,
    pub birth_place: Option<EncString>,
    pub nationality: Option<EncString>,
    pub issuing_country: Option<EncString>,
    pub passport_number: Option<EncString>,
    pub passport_type: Option<EncString>,
    pub national_identification_number: Option<EncString>,
    pub issuing_authority: Option<EncString>,
    pub issue_date: Option<EncString>,
    pub expiration_date: Option<EncString>,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct PassportView {
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

impl CompositeEncryptable<KeySlotIds, SymmetricKeySlotId, Passport> for PassportView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<Passport, CryptoError> {
        Ok(Passport {
            surname: self.surname.encrypt(ctx, key)?,
            given_name: self.given_name.encrypt(ctx, key)?,
            date_of_birth: self.date_of_birth.encrypt(ctx, key)?,
            sex: self.sex.encrypt(ctx, key)?,
            birth_place: self.birth_place.encrypt(ctx, key)?,
            nationality: self.nationality.encrypt(ctx, key)?,
            issuing_country: self.issuing_country.encrypt(ctx, key)?,
            passport_number: self.passport_number.encrypt(ctx, key)?,
            passport_type: self.passport_type.encrypt(ctx, key)?,
            national_identification_number: self
                .national_identification_number
                .encrypt(ctx, key)?,
            issuing_authority: self.issuing_authority.encrypt(ctx, key)?,
            issue_date: self.issue_date.encrypt(ctx, key)?,
            expiration_date: self.expiration_date.encrypt(ctx, key)?,
        })
    }
}

impl Decryptable<KeySlotIds, SymmetricKeySlotId, PassportView> for Passport {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<PassportView, CryptoError> {
        Ok(PassportView {
            surname: self.surname.decrypt(ctx, key).ok().flatten(),
            given_name: self.given_name.decrypt(ctx, key).ok().flatten(),
            date_of_birth: self.date_of_birth.decrypt(ctx, key).ok().flatten(),
            sex: self.sex.decrypt(ctx, key).ok().flatten(),
            birth_place: self.birth_place.decrypt(ctx, key).ok().flatten(),
            nationality: self.nationality.decrypt(ctx, key).ok().flatten(),
            issuing_country: self.issuing_country.decrypt(ctx, key).ok().flatten(),
            passport_number: self.passport_number.decrypt(ctx, key).ok().flatten(),
            passport_type: self.passport_type.decrypt(ctx, key).ok().flatten(),
            national_identification_number: self
                .national_identification_number
                .decrypt(ctx, key)
                .ok()
                .flatten(),
            issuing_authority: self.issuing_authority.decrypt(ctx, key).ok().flatten(),
            issue_date: self.issue_date.decrypt(ctx, key).ok().flatten(),
            expiration_date: self.expiration_date.decrypt(ctx, key).ok().flatten(),
        })
    }
}

impl CipherKind for Passport {
    fn decrypt_subtitle(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<String, CryptoError> {
        let given_name: Option<String> = self
            .given_name
            .as_ref()
            .map(|g| g.decrypt(ctx, key))
            .transpose()?;
        let surname: Option<String> = self
            .surname
            .as_ref()
            .map(|s| s.decrypt(ctx, key))
            .transpose()?;
        let parts: Vec<String> = [given_name, surname]
            .into_iter()
            .flatten()
            .filter(|s| !s.is_empty())
            .collect();
        Ok(parts.join(" "))
    }

    fn get_copyable_fields(&self, _: Option<&Cipher>) -> Vec<CopyableCipherFields> {
        [self
            .passport_number
            .as_ref()
            .map(|_| CopyableCipherFields::PassportPassportNumber)]
        .into_iter()
        .flatten()
        .collect()
    }
}

impl TryFrom<CipherPassportModel> for Passport {
    type Error = VaultParseError;

    fn try_from(passport: CipherPassportModel) -> Result<Self, Self::Error> {
        Ok(Self {
            surname: EncString::try_from_optional(passport.surname)?,
            given_name: EncString::try_from_optional(passport.given_name)?,
            date_of_birth: EncString::try_from_optional(passport.date_of_birth)?,
            sex: EncString::try_from_optional(passport.sex)?,
            birth_place: EncString::try_from_optional(passport.birth_place)?,
            nationality: EncString::try_from_optional(passport.nationality)?,
            issuing_country: EncString::try_from_optional(passport.issuing_country)?,
            passport_number: EncString::try_from_optional(passport.passport_number)?,
            passport_type: EncString::try_from_optional(passport.passport_type)?,
            national_identification_number: EncString::try_from_optional(
                passport.national_identification_number,
            )?,
            issuing_authority: EncString::try_from_optional(passport.issuing_authority)?,
            issue_date: EncString::try_from_optional(passport.issue_date)?,
            expiration_date: EncString::try_from_optional(passport.expiration_date)?,
        })
    }
}

impl From<Passport> for CipherPassportModel {
    fn from(passport: Passport) -> Self {
        Self {
            surname: passport.surname.map(|n| n.to_string()),
            given_name: passport.given_name.map(|n| n.to_string()),
            date_of_birth: passport.date_of_birth.map(|n| n.to_string()),
            sex: passport.sex.map(|n| n.to_string()),
            birth_place: passport.birth_place.map(|n| n.to_string()),
            nationality: passport.nationality.map(|n| n.to_string()),
            issuing_country: passport.issuing_country.map(|n| n.to_string()),
            passport_number: passport.passport_number.map(|n| n.to_string()),
            passport_type: passport.passport_type.map(|n| n.to_string()),
            national_identification_number: passport
                .national_identification_number
                .map(|n| n.to_string()),
            issuing_authority: passport.issuing_authority.map(|n| n.to_string()),
            issue_date: passport.issue_date.map(|n| n.to_string()),
            expiration_date: passport.expiration_date.map(|n| n.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::create_test_crypto_with_user_key;
    use bitwarden_crypto::SymmetricCryptoKey;

    use super::*;
    use crate::cipher::cipher::CopyableCipherFields;

    const TEST_VECTOR_PASSPORT_KEY: &str =
        "eG6fDUuqSQFpX6ACdw2u65PkLKDiOk9aQfUgUC/BTU3+UFpAPP/CtE7b+ZdeK3SC2z5+rWvhm537jV3qIbzIBA==";
    const TEST_VECTOR_PASSPORT_JSON: &str = r#"{"surname":"2.eQaSEApRodSjkXYijwVKog==|2gQz6ddMxUt3p400Axj43w==|XR6WmolSiIMD/DhF0SBZr7Qjb56fgSlQWyH8fb8LiL4=","givenName":"2.hS8vFkgoKxe31l8tOJT6vA==|DuciBPcIw4TgX7kobPc6dQ==|oRbxAqSJx5T5KBcPLhHhhJnQKjE5FjORIe9K41rXJKg=","dateOfBirth":"2.EQAdb/+PO6qGNTqYaufPYw==|dbUIcfU2w+zrtbxKcx1j2w==|F7AVClD4oXjS+1bqZtF8ociq/Gk8gPCi7cvtvjRNhF4=","sex":"2.pz3uUyCEKc5+1njtMm3lwg==|vB2Nyw9Dp/xKoTt/qPe30Q==|GuVXp0o6dxpV3iEdi2ifR5dTTd8XsiGE7LYFrpKVIIs=","birthPlace":"2.lGurnrRwJlAjugpdo9CdxQ==|kHdvvlXOsdgUNAMfUvIMoQ==|7pX2hZqP9S8srwEEzlZ2ZZCC2LUUzTiaHT/WBrPzb4A=","nationality":"2.0+Mjb6gfkirfw/cmHNIT8g==|GFLjpeEbID6jBS3a7/vvEA==|k0v1ArEI+iApsSj9UtucdsWD4hoM6vUjlHvRCI7bIz8=","issuingCountry":"2.PQhrBI1z8AJSzU9C07RkFA==|5OP/JHxFhEF/P8sKaTmwuA==|07Bfry57nZRyejesniXXt4xhgr4CN2JOSLVUHoDRL8Q=","passportNumber":"2.W+F0jcn8wY3W5d91zPwMTQ==|ny+5nUgNuiZ3SJR3Xbvsgg==|haWOAdcDbhs95hOsFknn5ABFbYm9B0Z7DoLN1hLaYEk=","passportType":"2.HO4v3tQ0QjZfazo5NxleZA==|fra59Rz9NKyrhoasK0UrEg==|n30Gb2pqLWtM8dzkfhsels76k9+7oWWqicK4kA10Hlw=","nationalIdentificationNumber":"2.+8kGWruSfQMZdXeB3X2s8Q==|KJp8B2lLNrmBFsCjN0u5dw==|zgW3uKX75k8/oFiEJEoXbcqeqiNI2jZZEeR8VQjF4jE=","issuingAuthority":"2.vDHido+bznW03M/CM9uY8g==|ryQ4ohHijQeEI8Fh3Rv1tA1eeCUqCsMuIGdGawJzSmo=|XbH99VX1LqpgVwzom6aHTsEUgoe5NekwRi0Fg7fKD8o=","issueDate":"2.rvY/6OVEEGxhLVMgFhT4gQ==|9/g9m7753eM2B3m6raLghw==|IsVUOXJ5r/J/P5M2kq5MJ7viDVZbkMP2opggVCiImmY=","expirationDate":"2.yIMuc7J5yxerSuZaYY0sbQ==|VIGDsMYFoUmJaVZ/ZR+gtg==|rMWvQHK24zUqZQnJgTNL58W71/ZJA/Dx3ernx4JRVVQ="}"#;

    fn test_passport_view() -> PassportView {
        PassportView {
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

        let encrypted = test_passport_view()
            .encrypt_composite(&mut ctx, key_slot)
            .unwrap();
        let json = serde_json::to_string(&encrypted).unwrap();

        println!("const TEST_VECTOR_PASSPORT_KEY: &str = \"{key_b64}\";");
        println!("const TEST_VECTOR_PASSPORT_JSON: &str = r#\"{json}\"#;");
    }

    #[test]
    fn test_recorded_passport_test_vector() {
        let key = SymmetricCryptoKey::try_from(TEST_VECTOR_PASSPORT_KEY.to_string())
            .expect("valid test key");
        let key_store = create_test_crypto_with_user_key(key);
        let key_slot = SymmetricKeySlotId::User;
        let mut ctx = key_store.context();

        let encrypted: Passport =
            serde_json::from_str(TEST_VECTOR_PASSPORT_JSON).expect("valid test vector JSON");
        let decrypted: PassportView = encrypted
            .decrypt(&mut ctx, key_slot)
            .expect("Passport has changed in a backwards-incompatible way. Existing encrypted data must remain decryptable. If a new format is needed, create a new version instead of modifying the existing one.");

        assert_eq!(decrypted, test_passport_view());
    }

    #[test]
    fn test_subtitle_passport() {
        let key = SymmetricCryptoKey::try_from("hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw==".to_string()).unwrap();
        let key_store = create_test_crypto_with_user_key(key);
        let key = SymmetricKeySlotId::User;
        let mut ctx = key_store.context();

        let given_name_encrypted = "Jane".to_owned().encrypt(&mut ctx, key).unwrap();
        let surname_encrypted = "Doe".to_owned().encrypt(&mut ctx, key).unwrap();

        let passport = Passport {
            surname: Some(surname_encrypted),
            given_name: Some(given_name_encrypted),
            date_of_birth: None,
            sex: None,
            birth_place: None,
            nationality: None,
            issuing_country: None,
            passport_number: None,
            passport_type: None,
            national_identification_number: None,
            issuing_authority: None,
            issue_date: None,
            expiration_date: None,
        };

        assert_eq!(
            passport.decrypt_subtitle(&mut ctx, key).unwrap(),
            "Jane Doe".to_string()
        );
    }

    #[test]
    fn test_get_copyable_fields_passport() {
        let enc_str: EncString = "2.tMIugb6zQOL+EuOizna1wQ==|W5dDLoNJtajN68yeOjrr6w==|qS4hwJB0B0gNLI0o+jxn+sKMBmvtVgJCRYNEXBZoGeE=".parse().unwrap();

        let passport = Passport {
            surname: Some(enc_str.clone()),
            given_name: Some(enc_str.clone()),
            date_of_birth: Some(enc_str.clone()),
            sex: Some(enc_str.clone()),
            birth_place: Some(enc_str.clone()),
            nationality: Some(enc_str.clone()),
            issuing_country: Some(enc_str.clone()),
            passport_number: Some(enc_str.clone()),
            passport_type: Some(enc_str.clone()),
            national_identification_number: Some(enc_str.clone()),
            issuing_authority: Some(enc_str.clone()),
            issue_date: Some(enc_str.clone()),
            expiration_date: Some(enc_str),
        };

        let copyable_fields = passport.get_copyable_fields(None);
        assert_eq!(
            copyable_fields,
            vec![CopyableCipherFields::PassportPassportNumber,]
        );
    }
}
