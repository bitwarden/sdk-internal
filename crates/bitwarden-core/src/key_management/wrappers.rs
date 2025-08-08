use std::ops::Deref;

use serde::{Deserialize, Serialize};
use tsify::Tsify;

use crate::key_management::KeyIds;

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct DataEnvelope(
    #[cfg_attr(feature = "wasm", tsify(type = r#"Tagged<string, "DataEnvelope">"#))]
    bitwarden_crypto::safe::DataEnvelope<crate::key_management::KeyIds>,
);

impl From<DataEnvelope> for bitwarden_crypto::safe::DataEnvelope<crate::key_management::KeyIds> {
    fn from(val: DataEnvelope) -> Self {
        val.0
    }
}

impl From<bitwarden_crypto::safe::DataEnvelope<crate::key_management::KeyIds>> for DataEnvelope {
    fn from(val: bitwarden_crypto::safe::DataEnvelope<crate::key_management::KeyIds>) -> Self {
        DataEnvelope(val)
    }
}

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

impl Clone for DataEnvelope {
    fn clone(&self) -> Self {
        DataEnvelope(self.0.clone())
    }
}
