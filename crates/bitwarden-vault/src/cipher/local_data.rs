use bitwarden_crypto::{
    CryptoError, EncryptionContext, KeyDecryptable, KeyEncryptable, NoContext, NoContextBuilder,
    SymmetricCryptoKey,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct LocalData {
    last_used_date: Option<u32>,
    last_launched: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct LocalDataView {
    last_used_date: Option<u32>,
    last_launched: Option<u32>,
}

impl KeyEncryptable<SymmetricCryptoKey, LocalData, NoContext> for LocalDataView {
    fn encrypt_with_key(
        self,
        _key: &SymmetricCryptoKey,
        _context: &NoContext,
    ) -> Result<LocalData, CryptoError> {
        Ok(LocalData {
            last_used_date: self.last_used_date,
            last_launched: self.last_launched,
        })
    }
}

impl KeyDecryptable<SymmetricCryptoKey, LocalDataView, NoContextBuilder> for LocalData {
    fn decrypt_with_key(
        &self,
        _key: &SymmetricCryptoKey,
        _context_builder: &NoContextBuilder,
    ) -> Result<LocalDataView, CryptoError> {
        Ok(LocalDataView {
            last_used_date: self.last_used_date,
            last_launched: self.last_launched,
        })
    }
}
