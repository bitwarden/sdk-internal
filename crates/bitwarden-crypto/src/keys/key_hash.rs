use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
pub(crate) enum KeyHashAlgorithm {
    Blake3,
}

impl KeyHashAlgorithm {
    pub(crate) fn to_string(&self) -> String {
        match self {
            Self::Blake3 => "blake3".to_string(),
        }
    }
}

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
pub(crate) struct KeyHash {
    pub(crate) hash: Vec<u8>,
    pub(crate) algorithm: KeyHashAlgorithm,
}

impl KeyHash {
    pub(crate) fn to_string(&self) -> String {
        format!(
            "{}:{}",
            self.algorithm.to_string(),
            STANDARD.encode(&self.hash)
        )
    }
}

pub(crate) trait KeyHashable {
     fn hash(&self) -> KeyHash;
}

impl<T: KeyHashData> KeyHashable for T {
    fn hash(&self) -> KeyHash {
        let hash: [u8; 32] = blake3::hash(&self.hash_data()).into();
        KeyHash {
            hash: hash.to_vec(),
            algorithm: KeyHashAlgorithm::Blake3,
        }
    }
}

pub(crate) trait KeyHashData {
    fn hash_data(&self) -> Vec<u8>;
}