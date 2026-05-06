use super::{PassportDataV1, PassportView};

impl_bidirectional_from!(
    PassportView,
    PassportDataV1,
    [
        surname,
        given_name,
        date_of_birth,
        sex,
        birth_place,
        nationality,
        issuing_country,
        passport_number,
        passport_type,
        national_identification_number,
        issuing_authority,
        issue_date,
        expiration_date,
    ]
);

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
