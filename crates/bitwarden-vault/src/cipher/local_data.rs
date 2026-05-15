use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
use bitwarden_crypto::{CompositeEncryptable, CryptoError, Decryptable, KeyStoreContext};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct LocalData {
    last_used_date: Option<Timestamp>,
    last_launched: Option<Timestamp>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct LocalDataView {
    last_used_date: Option<Timestamp>,
    last_launched: Option<Timestamp>,
}

impl CompositeEncryptable<KeySlotIds, SymmetricKeySlotId, LocalData> for LocalDataView {
    fn encrypt_composite(
        &self,
        _ctx: &mut KeyStoreContext<KeySlotIds>,
        _key: SymmetricKeySlotId,
    ) -> Result<LocalData, CryptoError> {
        Ok(LocalData {
            last_used_date: self.last_used_date,
            last_launched: self.last_launched,
        })
    }
}

impl Decryptable<KeySlotIds, SymmetricKeySlotId, LocalDataView> for LocalData {
    fn decrypt(
        &self,
        _ctx: &mut KeyStoreContext<KeySlotIds>,
        _key: SymmetricKeySlotId,
    ) -> Result<LocalDataView, CryptoError> {
        Ok(LocalDataView {
            last_used_date: self.last_used_date,
            last_launched: self.last_launched,
        })
    }
}
