use bitwarden_api_api::models::CipherCardModel;
use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{CryptoError, Decryptable, EncString, Encryptable, KeyStoreContext};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify_next::Tsify;

use crate::VaultParseError;

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
