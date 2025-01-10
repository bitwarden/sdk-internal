use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

use crate::CryptoError;

#[derive(PartialEq, Serialize, Deserialize)]
pub(crate) enum KeyHashAlgorithm {
    Blake3,
}

impl KeyHashAlgorithm {
    pub(crate) fn from_str(s: &str) -> Option<Self> {
        match s {
            "blake3" => Some(Self::Blake3),
            _ => None,
        }
    }

    pub(crate) fn to_string(&self) -> String {
        match self {
            Self::Blake3 => "blake3".to_string(),
        }
    }
}

#[derive(PartialEq, Serialize, Deserialize)]
pub(crate) struct KeyHash {
    pub(crate) hash: Vec<u8>,
    pub(crate) algorithm: KeyHashAlgorithm,
}

impl KeyHash {
    pub(crate) fn from_str(s: &str) -> Result<Self, CryptoError> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(CryptoError::HashParseError);
        }

        let algorithm =
            KeyHashAlgorithm::from_str(parts[0]).ok_or(CryptoError::InvalidHashAlgorithm)?;
        let hash = STANDARD
            .decode(parts[1])
            .map_err(|_| CryptoError::HashParseError)?;

        Ok(Self { algorithm, hash })
    }

    pub(crate) fn to_string(&self) -> String {
        format!(
            "{}:{}",
            self.algorithm.to_string(),
            STANDARD.encode(&self.hash)
        )
    }

    /// only for debugging
    pub(crate) fn default() -> Self {
        Self {
            hash: vec![0; 32],
            algorithm: KeyHashAlgorithm::Blake3,
        }
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
