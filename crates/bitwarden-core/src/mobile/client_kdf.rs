use bitwarden_crypto::{CryptoError, HashPurpose, Kdf};

use crate::{mobile::kdf::hash_password, Client};

/// A client for the KDF operations.
pub struct KdfClient {
    pub(crate) _client: crate::Client,
}

impl KdfClient {
    /// Hashes the password using the provided KDF parameters and purpose.
    pub async fn hash_password(
        &self,
        email: String,
        password: String,
        kdf_params: Kdf,
        purpose: HashPurpose,
    ) -> Result<String, CryptoError> {
        hash_password(email, password, kdf_params, purpose).await
    }
}

impl Client {
    /// Access to KDF functionality.
    pub fn kdf(&self) -> KdfClient {
        KdfClient {
            _client: self.clone(),
        }
    }
}
