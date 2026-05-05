use super::{DriversLicenseDataV1, DriversLicenseView};

impl_bidirectional_from!(
    DriversLicenseView,
    DriversLicenseDataV1,
    [
        first_name,
        middle_name,
        last_name,
        date_of_birth,
        license_number,
        issuing_country,
        issuing_state,
        issue_date,
        expiration_date,
        issuing_authority,
        license_class,
    ]
);

#[cfg(test)]
mod tests {
    use super::super::{CipherBlobV1, test_support::*};
    use crate::cipher::{cipher::CipherType, drivers_license::DriversLicenseView};

    #[test]
    fn test_drivers_license_cipher_round_trip() {
        let (key_store, key_id) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let original = crate::CipherView {
            name: "My Driver's License".to_string(),
            notes: None,
            r#type: CipherType::DriversLicense,
            drivers_license: Some(DriversLicenseView {
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
            ..create_shell_cipher_view(CipherType::DriversLicense)
        };

        let blob = CipherBlobV1::from_cipher_view(&original, &mut ctx, key_id).unwrap();
        let mut restored = create_shell_cipher_view(CipherType::DriversLicense);
        blob.apply_to_cipher_view(&mut restored, &mut ctx, key_id)
            .unwrap();

        assert_eq!(restored.name, "My Driver's License");
        assert_eq!(restored.r#type, CipherType::DriversLicense);
        let dl = restored.drivers_license.unwrap();
        assert_eq!(dl.first_name, Some("John".to_string()));
        assert_eq!(dl.license_number, Some("DL-987654".to_string()));
        assert!(restored.login.is_none());
    }
}
