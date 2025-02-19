use serde::{Deserialize, Serialize};

use crate::key_hash;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) enum AdditionalData {
    // On old ciphers that do not use AEAD
    #[serde(rename = "none")]
    None,
    #[serde(rename = "v0")]
    V0(AdditionalDataV0),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct AdditionalDataV0 {
    #[serde(rename = "ekh")]
    pub(crate) encrypting_key_hash: key_hash::KeyHash,
    #[serde(rename = "ad")]
    pub(crate) domain_ad: DomainSpecificAdditionalData,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) enum DomainSpecificAdditionalData {
    #[serde(rename = "none")]
    None,
    // e.g. MasterKeyEncryptedUserKey, Cipher, etc.
}
