use super::{DriversLicenseDataV1, DriversLicenseView};

impl From<&DriversLicenseView> for DriversLicenseDataV1 {
    fn from(src: &DriversLicenseView) -> Self {
        Self {
            first_name: src.first_name.clone(),
            middle_name: src.middle_name.clone(),
            last_name: src.last_name.clone(),
            date_of_birth: src.date_of_birth.map(|d| d.to_string()),
            license_number: src.license_number.clone(),
            issuing_country: src.issuing_country.clone(),
            issuing_state: src.issuing_state.clone(),
            issue_date: src.issue_date.map(|d| d.to_string()),
            expiration_date: src.expiration_date.map(|d| d.to_string()),
            issuing_authority: src.issuing_authority.clone(),
            license_class: src.license_class.clone(),
        }
    }
}

impl From<&DriversLicenseDataV1> for DriversLicenseView {
    fn from(src: &DriversLicenseDataV1) -> Self {
        Self {
            first_name: src.first_name.clone(),
            middle_name: src.middle_name.clone(),
            last_name: src.last_name.clone(),
            date_of_birth: src.date_of_birth.as_deref().and_then(|s| s.parse().ok()),
            license_number: src.license_number.clone(),
            issuing_country: src.issuing_country.clone(),
            issuing_state: src.issuing_state.clone(),
            issue_date: src.issue_date.as_deref().and_then(|s| s.parse().ok()),
            expiration_date: src.expiration_date.as_deref().and_then(|s| s.parse().ok()),
            issuing_authority: src.issuing_authority.clone(),
            license_class: src.license_class.clone(),
        }
    }
}

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
                date_of_birth: chrono::NaiveDate::from_ymd_opt(1985, 6, 15),
                license_number: Some("DL-987654".to_string()),
                issuing_country: Some("US".to_string()),
                issuing_state: Some("NY".to_string()),
                issue_date: chrono::NaiveDate::from_ymd_opt(2020, 1, 1),
                expiration_date: chrono::NaiveDate::from_ymd_opt(2028, 1, 1),
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
