use serde::{Deserialize, Serialize};

use crate::key_hash;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) enum AdditionalData {
    // On old ciphers that do not use AEAD
    None,
    V0(AdditionalDataV0),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct AdditionalDataV0 {
    #[serde(rename = "enc_key_hash")]
    pub(crate) encrypting_key_hash: key_hash::KeyHash,
    pub(crate) domain_ad: DomainSpecificAdditionalData,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) enum DomainSpecificAdditionalData {
    None,
    // e.g. MasterKeyEncryptedUserKey, Cipher, etc.
}
