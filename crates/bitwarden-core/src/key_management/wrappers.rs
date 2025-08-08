use std::ops::Deref;

use serde::{Deserialize, Serialize};
use tsify_next::Tsify;

use crate::key_management::KeyIds;

#[derive(Serialize, Deserialize, Clone)]
#[serde(transparent)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct DataEnvelope(
    pub(crate) bitwarden_crypto::safe::DataEnvelope<crate::key_management::KeyIds>,
);

impl Deref for DataEnvelope {
    type Target = bitwarden_crypto::safe::DataEnvelope<KeyIds>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for DataEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
