use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) enum AdditionalData {
    V0(AdditionalDataV0),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct AdditionalDataV0 {
    // key hash
    pub(crate) key_hash: String,
}
