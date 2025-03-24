use serde::{Deserialize, Serialize};

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
pub(crate) enum KeyHashAlgorithm {
    #[serde(rename = "b3")]
    Blake3,
}

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
pub(crate) struct KeyHash {
    #[serde(with = "serde_bytes", rename = "h")]
    pub(crate) hash: Vec<u8>,
    #[serde(rename = "alg")]
    pub(crate) algorithm: KeyHashAlgorithm,
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
