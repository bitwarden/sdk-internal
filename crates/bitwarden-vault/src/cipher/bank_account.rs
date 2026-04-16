use bitwarden_api_api::models::CipherBankAccountModel;
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
pub struct BankAccount {
    pub bank_name: Option<EncString>,
    pub name_on_account: Option<EncString>,
    pub account_type: Option<EncString>,
    pub account_number: Option<EncString>,
    pub routing_number: Option<EncString>,
    pub branch_number: Option<EncString>,
    pub pin: Option<EncString>,
    pub swift_code: Option<EncString>,
    pub iban: Option<EncString>,
    pub bank_contact_phone: Option<EncString>,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct BankAccountView {
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

impl CompositeEncryptable<KeySlotIds, SymmetricKeySlotId, BankAccount> for BankAccountView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<BankAccount, CryptoError> {
        Ok(BankAccount {
            bank_name: self.bank_name.encrypt(ctx, key)?,
            name_on_account: self.name_on_account.encrypt(ctx, key)?,
            account_type: self.account_type.encrypt(ctx, key)?,
            account_number: self.account_number.encrypt(ctx, key)?,
            routing_number: self.routing_number.encrypt(ctx, key)?,
            branch_number: self.branch_number.encrypt(ctx, key)?,
            pin: self.pin.encrypt(ctx, key)?,
            swift_code: self.swift_code.encrypt(ctx, key)?,
            iban: self.iban.encrypt(ctx, key)?,
            bank_contact_phone: self.bank_contact_phone.encrypt(ctx, key)?,
        })
    }
}

impl Decryptable<KeySlotIds, SymmetricKeySlotId, BankAccountView> for BankAccount {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<BankAccountView, CryptoError> {
        Ok(BankAccountView {
            bank_name: self.bank_name.decrypt(ctx, key).ok().flatten(),
            name_on_account: self.name_on_account.decrypt(ctx, key).ok().flatten(),
            account_type: self.account_type.decrypt(ctx, key).ok().flatten(),
            account_number: self.account_number.decrypt(ctx, key).ok().flatten(),
            routing_number: self.routing_number.decrypt(ctx, key).ok().flatten(),
            branch_number: self.branch_number.decrypt(ctx, key).ok().flatten(),
            pin: self.pin.decrypt(ctx, key).ok().flatten(),
            swift_code: self.swift_code.decrypt(ctx, key).ok().flatten(),
            iban: self.iban.decrypt(ctx, key).ok().flatten(),
            bank_contact_phone: self.bank_contact_phone.decrypt(ctx, key).ok().flatten(),
        })
    }
}

impl CipherKind for BankAccount {
    fn decrypt_subtitle(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<String, CryptoError> {
        let bank_name = self
            .bank_name
            .as_ref()
            .map(|b| b.decrypt(ctx, key))
            .transpose()?;
        Ok(bank_name.unwrap_or_default())
    }

    fn get_copyable_fields(&self, _: Option<&Cipher>) -> Vec<CopyableCipherFields> {
        [
            self.account_number
                .as_ref()
                .map(|_| CopyableCipherFields::BankAccountAccountNumber),
            self.routing_number
                .as_ref()
                .map(|_| CopyableCipherFields::BankAccountRoutingNumber),
            self.pin
                .as_ref()
                .map(|_| CopyableCipherFields::BankAccountPin),
            self.iban
                .as_ref()
                .map(|_| CopyableCipherFields::BankAccountIban),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

impl TryFrom<CipherBankAccountModel> for BankAccount {
    type Error = VaultParseError;

    fn try_from(bank_account: CipherBankAccountModel) -> Result<Self, Self::Error> {
        Ok(Self {
            bank_name: EncString::try_from_optional(bank_account.bank_name)?,
            name_on_account: EncString::try_from_optional(bank_account.name_on_account)?,
            account_type: EncString::try_from_optional(bank_account.account_type)?,
            account_number: EncString::try_from_optional(bank_account.account_number)?,
            routing_number: EncString::try_from_optional(bank_account.routing_number)?,
            branch_number: EncString::try_from_optional(bank_account.branch_number)?,
            pin: EncString::try_from_optional(bank_account.pin)?,
            swift_code: EncString::try_from_optional(bank_account.swift_code)?,
            iban: EncString::try_from_optional(bank_account.iban)?,
            bank_contact_phone: EncString::try_from_optional(bank_account.bank_contact_phone)?,
        })
    }
}

impl From<BankAccount> for CipherBankAccountModel {
    fn from(bank_account: BankAccount) -> Self {
        Self {
            bank_name: bank_account.bank_name.map(|n| n.to_string()),
            name_on_account: bank_account.name_on_account.map(|n| n.to_string()),
            account_type: bank_account.account_type.map(|n| n.to_string()),
            account_number: bank_account.account_number.map(|n| n.to_string()),
            routing_number: bank_account.routing_number.map(|n| n.to_string()),
            branch_number: bank_account.branch_number.map(|n| n.to_string()),
            pin: bank_account.pin.map(|n| n.to_string()),
            swift_code: bank_account.swift_code.map(|n| n.to_string()),
            iban: bank_account.iban.map(|n| n.to_string()),
            bank_contact_phone: bank_account.bank_contact_phone.map(|n| n.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::create_test_crypto_with_user_key;
    use bitwarden_crypto::SymmetricCryptoKey;

    use super::*;
    use crate::cipher::cipher::CopyableCipherFields;

    #[test]
    fn test_subtitle_bank_account() {
        let key = SymmetricCryptoKey::try_from("hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw==".to_string()).unwrap();
        let key_store = create_test_crypto_with_user_key(key);
        let key = SymmetricKeySlotId::User;
        let mut ctx = key_store.context();

        let original_subtitle = "My Bank".to_string();
        let bank_name_encrypted = original_subtitle.to_owned().encrypt(&mut ctx, key).unwrap();

        let bank_account = BankAccount {
            bank_name: Some(bank_name_encrypted),
            name_on_account: None,
            account_type: None,
            account_number: None,
            routing_number: None,
            branch_number: None,
            pin: None,
            swift_code: None,
            iban: None,
            bank_contact_phone: None,
        };

        assert_eq!(
            bank_account.decrypt_subtitle(&mut ctx, key).unwrap(),
            original_subtitle
        );
    }

    #[test]
    fn test_get_copyable_fields_bank_account() {
        let enc_str: EncString = "2.tMIugb6zQOL+EuOizna1wQ==|W5dDLoNJtajN68yeOjrr6w==|qS4hwJB0B0gNLI0o+jxn+sKMBmvtVgJCRYNEXBZoGeE=".parse().unwrap();

        let bank_account = BankAccount {
            bank_name: Some(enc_str.clone()),
            name_on_account: Some(enc_str.clone()),
            account_type: Some(enc_str.clone()),
            account_number: Some(enc_str.clone()),
            routing_number: Some(enc_str.clone()),
            branch_number: Some(enc_str.clone()),
            pin: Some(enc_str.clone()),
            swift_code: Some(enc_str.clone()),
            iban: Some(enc_str.clone()),
            bank_contact_phone: Some(enc_str),
        };

        let copyable_fields = bank_account.get_copyable_fields(None);
        assert_eq!(
            copyable_fields,
            vec![
                CopyableCipherFields::BankAccountAccountNumber,
                CopyableCipherFields::BankAccountRoutingNumber,
                CopyableCipherFields::BankAccountPin,
                CopyableCipherFields::BankAccountIban,
            ]
        );
    }

    #[test]
    fn test_get_copyable_fields_bank_account_partial() {
        let enc_str: EncString = "2.tMIugb6zQOL+EuOizna1wQ==|W5dDLoNJtajN68yeOjrr6w==|qS4hwJB0B0gNLI0o+jxn+sKMBmvtVgJCRYNEXBZoGeE=".parse().unwrap();

        let bank_account = BankAccount {
            bank_name: None,
            name_on_account: None,
            account_type: None,
            account_number: Some(enc_str.clone()),
            routing_number: None,
            branch_number: None,
            pin: Some(enc_str),
            swift_code: None,
            iban: None,
            bank_contact_phone: None,
        };

        let copyable_fields = bank_account.get_copyable_fields(None);
        assert_eq!(
            copyable_fields,
            vec![
                CopyableCipherFields::BankAccountAccountNumber,
                CopyableCipherFields::BankAccountPin,
            ]
        );
    }
}
