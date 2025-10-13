use bitwarden_api_api::models::CipherCardModel;
use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
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

impl CompositeEncryptable<KeyIds, SymmetricKeyId, Card> for CardView {
    fn encrypt_composite(
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
    fn decrypt_subtitle(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<String, CryptoError> {
        let brand = self
            .brand
            .as_ref()
            .map(|b| b.decrypt(ctx, key))
            .transpose()?;
        let number = self
            .number
            .as_ref()
            .map(|n| n.decrypt(ctx, key))
            .transpose()?;

        Ok(build_subtitle_card(brand, number))
    }

    fn get_copyable_fields(&self, _: Option<&Cipher>) -> Vec<CopyableCipherFields> {
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

/// Builds the subtitle for a card cipher
fn build_subtitle_card(brand: Option<String>, number: Option<String>) -> String {
    // Attempt to pre-allocate the string with the expected max-size
    let mut subtitle =
        String::with_capacity(brand.as_ref().map(|b| b.len()).unwrap_or_default() + 8);

    if let Some(brand) = brand {
        subtitle.push_str(&brand);
    }

    if let Some(number) = number {
        let number_chars: Vec<_> = number.chars().collect();
        let number_len = number_chars.len();
        if number_len > 4 {
            if !subtitle.is_empty() {
                subtitle.push_str(", ");
            }

            // On AMEX cards we show 5 digits instead of 4
            let digit_count = match number_chars[0..2] {
                ['3', '4'] | ['3', '7'] => 5,
                _ => 4,
            };

            subtitle.push('*');
            subtitle.extend(number_chars.iter().skip(number_len - digit_count));
        }
    }

    subtitle
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_subtitle_card_visa() {
        let brand = Some("Visa".to_owned());
        let number = Some("4111111111111111".to_owned());

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "Visa, *1111");
    }

    #[test]
    fn test_build_subtitle_card_mastercard() {
        let brand = Some("Mastercard".to_owned());
        let number = Some("5555555555554444".to_owned());

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "Mastercard, *4444");
    }

    #[test]
    fn test_build_subtitle_card_amex() {
        let brand = Some("Amex".to_owned());
        let number = Some("378282246310005".to_owned());

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "Amex, *10005");
    }

    #[test]
    fn test_build_subtitle_card_underflow() {
        let brand = Some("Mastercard".to_owned());
        let number = Some("4".to_owned());

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "Mastercard");
    }

    #[test]
    fn test_build_subtitle_card_only_brand() {
        let brand = Some("Mastercard".to_owned());
        let number = None;

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "Mastercard");
    }

    #[test]
    fn test_build_subtitle_card_only_card() {
        let brand = None;
        let number = Some("5555555555554444".to_owned());

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "*4444");
    }
    #[test]
    fn test_get_copyable_fields_code() {
        let card = Card {
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: Some("2.6TpmzzaQHgYr+mXjdGLQlg==|vT8VhfvMlWSCN9hxGYftZ5rjKRsZ9ofjdlUCx5Gubnk=|uoD3/GEQBWKKx2O+/YhZUCzVkfhm8rFK3sUEVV84mv8=".parse().unwrap()),
            brand: None,
            number: None,
        };

        let copyable_fields = card.get_copyable_fields(None);

        assert_eq!(
            copyable_fields,
            vec![CopyableCipherFields::CardSecurityCode]
        );
    }

    #[test]
    fn test_build_subtitle_card_unicode() {
        let brand = Some("Visa".to_owned());
        let number = Some("•••• 3278".to_owned());

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "Visa, *3278");
    }

    #[test]
    fn test_get_copyable_fields_number() {
        let card = Card {
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
            brand: None,
            number: Some("2.6TpmzzaQHgYr+mXjdGLQlg==|vT8VhfvMlWSCN9hxGYftZ5rjKRsZ9ofjdlUCx5Gubnk=|uoD3/GEQBWKKx2O+/YhZUCzVkfhm8rFK3sUEVV84mv8=".parse().unwrap()),
        };

        let copyable_fields = card.get_copyable_fields(None);

        assert_eq!(copyable_fields, vec![CopyableCipherFields::CardNumber]);
    }
}
