use super::{PassportDataV1, PassportView};

impl From<&PassportView> for PassportDataV1 {
    fn from(src: &PassportView) -> Self {
        Self {
            surname: src.surname.clone(),
            given_name: src.given_name.clone(),
            date_of_birth: src.date_of_birth.map(|d| d.to_string()),
            sex: src.sex.clone(),
            birth_place: src.birth_place.clone(),
            nationality: src.nationality.clone(),
            issuing_country: src.issuing_country.clone(),
            passport_number: src.passport_number.clone(),
            passport_type: src.passport_type.clone(),
            national_identification_number: src.national_identification_number.clone(),
            issuing_authority: src.issuing_authority.clone(),
            issue_date: src.issue_date.map(|d| d.to_string()),
            expiration_date: src.expiration_date.map(|d| d.to_string()),
        }
    }
}

impl From<&PassportDataV1> for PassportView {
    fn from(src: &PassportDataV1) -> Self {
        Self {
            surname: src.surname.clone(),
            given_name: src.given_name.clone(),
            date_of_birth: src.date_of_birth.as_deref().and_then(|s| s.parse().ok()),
            sex: src.sex.clone(),
            birth_place: src.birth_place.clone(),
            nationality: src.nationality.clone(),
            issuing_country: src.issuing_country.clone(),
            passport_number: src.passport_number.clone(),
            passport_type: src.passport_type.clone(),
            national_identification_number: src.national_identification_number.clone(),
            issuing_authority: src.issuing_authority.clone(),
            issue_date: src.issue_date.as_deref().and_then(|s| s.parse().ok()),
            expiration_date: src.expiration_date.as_deref().and_then(|s| s.parse().ok()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CipherBlobV1, test_support::*};
    use crate::cipher::{cipher::CipherType, passport::PassportView};

    #[test]
    fn test_passport_cipher_round_trip() {
        let (key_store, key_id) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let original = crate::CipherView {
            name: "My Passport".to_string(),
            notes: None,
            r#type: CipherType::Passport,
            passport: Some(PassportView {
                surname: Some("Doe".to_string()),
                given_name: Some("Jane".to_string()),
                date_of_birth: chrono::NaiveDate::from_ymd_opt(1990, 1, 1),
                sex: Some("F".to_string()),
                birth_place: Some("New York".to_string()),
                nationality: Some("American".to_string()),
                issuing_country: Some("US".to_string()),
                passport_number: Some("P12345678".to_string()),
                passport_type: Some("P".to_string()),
                national_identification_number: Some("123-45-6789".to_string()),
                issuing_authority: Some("US State Department".to_string()),
                issue_date: chrono::NaiveDate::from_ymd_opt(2020, 1, 1),
                expiration_date: chrono::NaiveDate::from_ymd_opt(2030, 1, 1),
            }),
            ..create_shell_cipher_view(CipherType::Passport)
        };

        let blob = CipherBlobV1::from_cipher_view(&original, &mut ctx, key_id).unwrap();
        let mut restored = create_shell_cipher_view(CipherType::Passport);
        blob.apply_to_cipher_view(&mut restored, &mut ctx, key_id)
            .unwrap();

        assert_eq!(restored.name, "My Passport");
        assert_eq!(restored.r#type, CipherType::Passport);
        let passport = restored.passport.unwrap();
        assert_eq!(passport.surname, Some("Doe".to_string()));
        assert_eq!(passport.passport_number, Some("P12345678".to_string()));
        assert!(restored.login.is_none());
    }
}
