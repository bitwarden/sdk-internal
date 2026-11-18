use super::{CardDataV1, CardView};

impl_bidirectional_from!(
    CardView,
    CardDataV1,
    [cardholder_name, exp_month, exp_year, code, brand, number,]
);

#[cfg(test)]
mod tests {
    use super::super::{CipherBlobV1, test_support::*};
    use crate::cipher::{card::CardView, cipher::CipherType};

    #[test]
    fn test_card_cipher_round_trip() {
        let (key_store, key_id) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let original = crate::CipherView {
            name: "My Card".to_string(),
            notes: None,
            r#type: CipherType::Card,
            card: Some(CardView {
                cardholder_name: Some("John Doe".to_string()),
                exp_month: Some("12".to_string()),
                exp_year: Some("2028".to_string()),
                code: Some("123".to_string()),
                brand: Some("Visa".to_string()),
                number: Some("4111111111111111".to_string()),
            }),
            ..create_shell_cipher_view(CipherType::Card)
        };

        let blob = CipherBlobV1::from_cipher_view(&original, &mut ctx, key_id).unwrap();
        let mut restored = create_shell_cipher_view(CipherType::Card);
        blob.apply_to_cipher_view(&mut restored, &mut ctx, key_id)
            .unwrap();

        assert_eq!(restored.name, "My Card");
        assert_eq!(restored.r#type, CipherType::Card);
        let card = restored.card.unwrap();
        assert_eq!(card.cardholder_name, Some("John Doe".to_string()));
        assert_eq!(card.number, Some("4111111111111111".to_string()));
        assert!(restored.login.is_none());
    }
}
