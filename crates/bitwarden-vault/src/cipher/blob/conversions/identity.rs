use super::{IdentityDataV1, IdentityView};

impl_bidirectional_from!(
    IdentityView,
    IdentityDataV1,
    [
        title,
        first_name,
        middle_name,
        last_name,
        address1,
        address2,
        address3,
        city,
        state,
        postal_code,
        country,
        company,
        email,
        phone,
        ssn,
        username,
        passport_number,
        license_number,
    ]
);

#[cfg(test)]
mod tests {
    use super::super::{CipherBlobV1, test_support::*};
    use crate::cipher::{cipher::CipherType, identity::IdentityView};

    #[test]
    fn test_identity_cipher_round_trip() {
        let (key_store, key_id) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let original = crate::CipherView {
            name: "My Identity".to_string(),
            notes: Some("Identity notes".to_string()),
            r#type: CipherType::Identity,
            identity: Some(IdentityView {
                title: Some("Mr".to_string()),
                first_name: Some("John".to_string()),
                middle_name: None,
                last_name: Some("Doe".to_string()),
                address1: Some("123 Main St".to_string()),
                address2: None,
                address3: None,
                city: Some("NYC".to_string()),
                state: Some("NY".to_string()),
                postal_code: Some("10001".to_string()),
                country: Some("US".to_string()),
                company: None,
                email: Some("john@example.com".to_string()),
                phone: None,
                ssn: None,
                username: Some("johndoe".to_string()),
                passport_number: None,
                license_number: None,
            }),
            ..create_shell_cipher_view(CipherType::Identity)
        };

        let blob = CipherBlobV1::from_cipher_view(&original, &mut ctx, key_id).unwrap();
        let mut restored = create_shell_cipher_view(CipherType::Identity);
        blob.apply_to_cipher_view(&mut restored, &mut ctx, key_id)
            .unwrap();

        assert_eq!(restored.name, "My Identity");
        assert_eq!(restored.r#type, CipherType::Identity);
        let identity = restored.identity.unwrap();
        assert_eq!(identity.first_name, Some("John".to_string()));
        assert_eq!(identity.last_name, Some("Doe".to_string()));
        assert_eq!(identity.email, Some("john@example.com".to_string()));
        assert!(restored.login.is_none());
        assert!(restored.card.is_none());
    }
}
