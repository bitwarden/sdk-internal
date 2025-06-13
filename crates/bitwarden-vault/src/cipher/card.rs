use bitwarden_api_api::models::CipherCardModel;
use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{CryptoError, Decryptable, EncString, Encryptable, KeyStoreContext};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify_next::Tsify;

use crate::{
    cipher::cipher::{Cipher, CipherKind, CopyableCipherFields},
    VaultParseError,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct Card {
    pub cardholder_name: Option<EncString>,
    pub exp_month: Option<EncString>,
    pub exp_year: Option<EncString>,
    pub code: Option<EncString>,
    pub brand: Option<EncString>,
    pub number: Option<EncString>,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CardView {
    pub cardholder_name: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
}

/// Minimal CardView only including the needed details for list views
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CardListView {
    /// The brand of the card, e.g. Visa, Mastercard, etc.
    pub brand: Option<String>,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize)]
pub enum CardBrand {
    Visa,
    Mastercard,
    Amex,
    Discover,
    #[serde(rename = "Diners Club")]
    DinersClub,
    #[serde(rename = "JCB")]
    Jcb,
    Maestro,
    UnionPay,
    RuPay,
    #[serde(untagged)]
    Other,
}

impl Encryptable<KeyIds, SymmetricKeyId, Card> for CardView {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<Card, CryptoError> {
        Ok(Card {
            cardholder_name: self.cardholder_name.encrypt(ctx, key)?,
            exp_month: self.exp_month.encrypt(ctx, key)?,
            exp_year: self.exp_year.encrypt(ctx, key)?,
            code: self.code.encrypt(ctx, key)?,
            brand: self.brand.encrypt(ctx, key)?,
            number: self.number.encrypt(ctx, key)?,
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, CardListView> for Card {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<CardListView, CryptoError> {
        Ok(CardListView {
            brand: self.brand.decrypt(ctx, key).ok().flatten(),
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, CardView> for Card {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<CardView, CryptoError> {
        Ok(CardView {
            cardholder_name: self.cardholder_name.decrypt(ctx, key).ok().flatten(),
            exp_month: self.exp_month.decrypt(ctx, key).ok().flatten(),
            exp_year: self.exp_year.decrypt(ctx, key).ok().flatten(),
            code: self.code.decrypt(ctx, key).ok().flatten(),
            brand: self.brand.decrypt(ctx, key).ok().flatten(),
            number: self.number.decrypt(ctx, key).ok().flatten(),
        })
    }
}

impl TryFrom<CipherCardModel> for Card {
    type Error = VaultParseError;

    fn try_from(card: CipherCardModel) -> Result<Self, Self::Error> {
        Ok(Self {
            cardholder_name: EncString::try_from_optional(card.cardholder_name)?,
            exp_month: EncString::try_from_optional(card.exp_month)?,
            exp_year: EncString::try_from_optional(card.exp_year)?,
            code: EncString::try_from_optional(card.code)?,
            brand: EncString::try_from_optional(card.brand)?,
            number: EncString::try_from_optional(card.number)?,
        })
    }
}

impl CipherKind for Card {
    fn get_copyable_fields(&self, _: &Cipher) -> Vec<CopyableCipherFields> {
        [
            self.number
                .as_ref()
                .map(|_| CopyableCipherFields::CardNumber),
            self.code
                .as_ref()
                .map(|_| CopyableCipherFields::CardSecurityCode),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::{create_test_crypto_with_user_key, SymmetricKeyId};
    use bitwarden_crypto::{EncString, Encryptable, SymmetricCryptoKey};

    use crate::{
        card::Card,
        cipher::cipher::{CipherKind, CopyableCipherFields},
        Cipher, CipherRepromptType, CipherType,
    };

    fn encrypt_test_string(string: &str) -> EncString {
        let key = SymmetricCryptoKey::try_from("hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw==".to_string()).unwrap();
        let key_store = create_test_crypto_with_user_key(key);
        let key = SymmetricKeyId::User;
        let mut ctx = key_store.context();

        string.to_string().encrypt(&mut ctx, key).unwrap()
    }

    fn create_cipher_for_card(card: Card) -> Cipher {
        Cipher {
            id: Some("090c19ea-a61a-4df6-8963-262b97bc6266".parse().unwrap()),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            r#type: CipherType::Login,
            key: None,
            name: encrypt_test_string("My test cipher"),
            notes: None,
            login: None,
            identity: None,
            card: Some(card),
            secure_note: None,
            ssh_key: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: false,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            fields: None,
            password_history: None,
            creation_date: "2024-01-01T00:00:00.000Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-01-01T00:00:00.000Z".parse().unwrap(),
        }
    }

    #[test]
    fn test_get_copyable_fields_code() {
        let card = Card {
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: Some(encrypt_test_string("123")),
            brand: None,
            number: None,
        };

        let cipher = create_cipher_for_card(card.clone());
        let copyable_fields = card.get_copyable_fields(&cipher);

        assert_eq!(
            copyable_fields,
            vec![CopyableCipherFields::CardSecurityCode]
        );
    }

    #[test]
    fn test_get_copyable_fields_number() {
        let card = Card {
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
            brand: None,
            number: Some(encrypt_test_string("4242424242424242")),
        };

        let cipher = create_cipher_for_card(card.clone());
        let copyable_fields = card.get_copyable_fields(&cipher);

        assert_eq!(copyable_fields, vec![CopyableCipherFields::CardNumber]);
    }
}
