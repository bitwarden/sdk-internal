use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{CryptoError, Decryptable, Encryptable, KeyStoreContext};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify_next::Tsify;

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct LocalData {
    last_used_date: Option<u64>,
    last_launched: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct LocalDataView {
    last_used_date: Option<u64>,
    last_launched: Option<u64>,
}

impl Encryptable<KeyIds, SymmetricKeyId, LocalData> for LocalDataView {
    fn encrypt(
        &self,
        _ctx: &mut KeyStoreContext<KeyIds>,
        _key: SymmetricKeyId,
    ) -> Result<LocalData, CryptoError> {
        Ok(LocalData {
            last_used_date: self.last_used_date,
            last_launched: self.last_launched,
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, LocalDataView> for LocalData {
    fn decrypt(
        &self,
        _ctx: &mut KeyStoreContext<KeyIds>,
        _key: SymmetricKeyId,
    ) -> Result<LocalDataView, CryptoError> {
        Ok(LocalDataView {
            last_used_date: self.last_used_date,
            last_launched: self.last_launched,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::LocalData;

    #[test]
    fn test_large_timestamps() {
        // This JSON would have caused overflow with u32
        let overflow_json = r#"{ "lastUsedDate": 1744662575875, "lastLaunched": null }"#;

        let result = serde_json::from_str::<LocalData>(overflow_json);
        assert!(result.is_ok());
    }
}
