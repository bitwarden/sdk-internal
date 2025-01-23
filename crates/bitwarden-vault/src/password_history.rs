use bitwarden_api_api::models::CipherPasswordHistoryModel;
use bitwarden_crypto::{
    CryptoError, EncString, EncryptionContext, KeyDecryptable, KeyEncryptable, NoContextBuilder, SymmetricCryptoKey
};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::VaultParseError;

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PasswordHistory {
    password: EncString,
    last_used_date: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PasswordHistoryView {
    password: String,
    last_used_date: DateTime<Utc>,
}

impl<Context: EncryptionContext> KeyEncryptable<SymmetricCryptoKey, PasswordHistory, Context> for PasswordHistoryView {
    fn encrypt_with_key(self, key: &SymmetricCryptoKey, context: &Context) -> Result<PasswordHistory, CryptoError> {
        Ok(PasswordHistory {
            password: self.password.encrypt_with_key(key, context)?,
            last_used_date: self.last_used_date,
        })
    }
}

impl KeyDecryptable<SymmetricCryptoKey, PasswordHistoryView, NoContextBuilder> for PasswordHistory {
    fn decrypt_with_key(
        &self,
        key: &SymmetricCryptoKey,
        context_builder: &NoContextBuilder,
    ) -> Result<PasswordHistoryView, CryptoError> {
        Ok(PasswordHistoryView {
            password: self
                .password
                .decrypt_with_key(key, context_builder)
                .ok()
                .unwrap_or_default(),
            last_used_date: self.last_used_date,
        })
    }
}

impl TryFrom<CipherPasswordHistoryModel> for PasswordHistory {
    type Error = VaultParseError;

    fn try_from(model: CipherPasswordHistoryModel) -> Result<Self, Self::Error> {
        Ok(Self {
            password: model.password.parse()?,
            last_used_date: model.last_used_date.parse()?,
        })
    }
}
