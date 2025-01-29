use bitwarden_api_api::models::CipherCardModel;
use bitwarden_crypto::{
    CryptoError, EncString, EncryptionContext, KeyDecryptable, KeyEncryptable, NoContext,
    NoContextBuilder, SymmetricCryptoKey,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::VaultParseError;

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Card {
    pub cardholder_name: Option<EncString<NoContext>>,
    pub exp_month: Option<EncString<NoContext>>,
    pub exp_year: Option<EncString<NoContext>>,
    pub code: Option<EncString<NoContext>>,
    pub brand: Option<EncString<NoContext>>,
    pub number: Option<EncString<NoContext>>,
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

impl KeyEncryptable<SymmetricCryptoKey, Card, NoContext> for CardView {
    fn encrypt_with_key(
        self,
        key: &SymmetricCryptoKey,
        context: &NoContext,
    ) -> Result<Card, CryptoError> {
        Ok(Card {
            cardholder_name: self.cardholder_name.encrypt_with_key(key, context)?,
            exp_month: self.exp_month.encrypt_with_key(key, context)?,
            exp_year: self.exp_year.encrypt_with_key(key, context)?,
            code: self.code.encrypt_with_key(key, context)?,
            brand: self.brand.encrypt_with_key(key, context)?,
            number: self.number.encrypt_with_key(key, context)?,
        })
    }
}

impl KeyDecryptable<SymmetricCryptoKey, CardView, NoContextBuilder> for Card {
    fn decrypt_with_key(
        &self,
        key: &SymmetricCryptoKey,
        context_builder: &NoContextBuilder,
    ) -> Result<CardView, CryptoError> {
        Ok(CardView {
            cardholder_name: self
                .cardholder_name
                .decrypt_with_key(key, context_builder)
                .ok()
                .flatten(),
            exp_month: self
                .exp_month
                .decrypt_with_key(key, context_builder)
                .ok()
                .flatten(),
            exp_year: self
                .exp_year
                .decrypt_with_key(key, context_builder)
                .ok()
                .flatten(),
            code: self
                .code
                .decrypt_with_key(key, context_builder)
                .ok()
                .flatten(),
            brand: self
                .brand
                .decrypt_with_key(key, context_builder)
                .ok()
                .flatten(),
            number: self
                .number
                .decrypt_with_key(key, context_builder)
                .ok()
                .flatten(),
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
