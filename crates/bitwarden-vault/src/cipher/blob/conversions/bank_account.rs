use super::{BankAccountDataV1, BankAccountView};

impl_bidirectional_from!(
    BankAccountView,
    BankAccountDataV1,
    [
        bank_name,
        name_on_account,
        account_type,
        account_number,
        routing_number,
        branch_number,
        pin,
        swift_code,
        iban,
        bank_contact_phone,
    ]
);

#[cfg(test)]
mod tests {
    use super::super::{CipherBlobV1, test_support::*};
    use crate::cipher::{bank_account::BankAccountView, cipher::CipherType};

    #[test]
    fn test_bank_account_cipher_round_trip() {
        let (key_store, key_id) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let original = crate::CipherView {
            name: "My Bank Account".to_string(),
            notes: None,
            r#type: CipherType::BankAccount,
            bank_account: Some(BankAccountView {
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
            ..create_shell_cipher_view(CipherType::BankAccount)
        };

        let blob = CipherBlobV1::from_cipher_view(&original, &mut ctx, key_id).unwrap();
        let mut restored = create_shell_cipher_view(CipherType::BankAccount);
        blob.apply_to_cipher_view(&mut restored, &mut ctx, key_id)
            .unwrap();

        assert_eq!(restored.name, "My Bank Account");
        assert_eq!(restored.r#type, CipherType::BankAccount);
        let bank_account = restored.bank_account.unwrap();
        assert_eq!(bank_account.bank_name, Some("Test Bank".to_string()));
        assert_eq!(bank_account.account_number, Some("1234567890".to_string()));
        assert_eq!(bank_account.pin, Some("1234".to_string()));
        assert!(restored.login.is_none());
    }
}
