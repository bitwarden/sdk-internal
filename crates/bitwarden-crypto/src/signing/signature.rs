use base64::{prelude::BASE64_STANDARD, Engine};

use super::SignatureAlgorithm;
use crate::CryptoError;

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct Signature {
    algorithm: SignatureAlgorithm,
    pub(crate) data: Vec<u8>,
}

impl Signature {
    pub fn new(algorithm: SignatureAlgorithm, data: Vec<u8>) -> Self {
        Self { algorithm, data }
    }

    pub fn to_string(&self) -> String {
        format!(
            "{}:{}",
            self.algorithm.to_string(),
            BASE64_STANDARD.encode(&self.data)
        )
    }

    pub fn from_string(s: &str) -> Result<Self, CryptoError> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(CryptoError::SignatureParseError);
        }

        let algorithm =
            SignatureAlgorithm::from_str(parts[0]).ok_or(CryptoError::InvalidSignatureAlgorithm)?;
        let data = BASE64_STANDARD
            .decode(parts[1])
            .map_err(|_| CryptoError::SignatureParseError)?;

        Ok(Self { algorithm, data })
    }

    pub fn algorithm(&self) -> &SignatureAlgorithm {
        &self.algorithm
    }
}
