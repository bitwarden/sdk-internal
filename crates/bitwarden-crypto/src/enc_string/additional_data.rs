use serde::{Deserialize, Serialize};

use crate::key_hash;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) enum AdditionalData {
    V0(AdditionalDataV0),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct AdditionalDataV0 {
    pub(crate) key_hash: key_hash::KeyHash,
}
