use bitwarden_api_api::models::CipherCardModel;
use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{CryptoError, Decryptable, EncString, Encryptable, KeyStoreContext};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::VaultParseError;

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Card {
    pub cardholder_name: Option<EncString>,
    pub exp_month: Option<EncString>,
    pub exp_year: Option<EncString>,
    pub code: Option<EncString>,
    pub brand: Option<EncString>,
    pub number: Option<EncString>,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CardView {
    pub cardholder_name: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
}

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
