use bitwarden_api_api::models::CipherPasswordHistoryModel;
use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, Decryptable, EncString, IdentifyKey, KeyStoreContext,
    PrimitiveEncryptable,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::VaultParseError;

/// Maximum number of password history entries to retain
pub(crate) const MAX_PASSWORD_HISTORY_ENTRIES: usize = 5;

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct PasswordHistory {
    password: EncString,
    last_used_date: DateTime<Utc>,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct PasswordHistoryView {
    pub password: String,
    pub last_used_date: DateTime<Utc>,
}

impl IdentifyKey<SymmetricKeyId> for PasswordHistory {
    fn key_identifier(&self) -> SymmetricKeyId {
        SymmetricKeyId::User
    }
}
impl IdentifyKey<SymmetricKeyId> for PasswordHistoryView {
    fn key_identifier(&self) -> SymmetricKeyId {
        SymmetricKeyId::User
    }
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, PasswordHistory> for PasswordHistoryView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<PasswordHistory, CryptoError> {
        Ok(PasswordHistory {
            password: self.password.encrypt(ctx, key)?,
            last_used_date: self.last_used_date,
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, PasswordHistoryView> for PasswordHistory {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<PasswordHistoryView, CryptoError> {
        Ok(PasswordHistoryView {
            password: self.password.decrypt(ctx, key).ok().unwrap_or_default(),
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

impl From<PasswordHistory> for CipherPasswordHistoryModel {
    fn from(history: PasswordHistory) -> Self {
        Self {
            password: history.password.to_string(),
            last_used_date: history.last_used_date.to_rfc3339(),
        }
    }
}

impl PasswordHistoryView {
    pub(crate) fn new_password(old_password: &str) -> Self {
        Self {
            password: old_password.to_string(),
            last_used_date: Utc::now(),
        }
    }

    pub(crate) fn new_field(field_name: &str, old_value: &str) -> Self {
        Self {
            password: format!("{field_name}: {old_value}"),
            last_used_date: Utc::now(),
        }
    }
}
