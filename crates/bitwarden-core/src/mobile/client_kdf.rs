use bitwarden_crypto::{CryptoError, HashPurpose, Kdf};

use crate::{mobile::kdf::hash_password, Client};

pub struct ClientKdf {
    pub(crate) _client: crate::Client,
}

impl ClientKdf {
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
    pub fn kdf(&self) -> ClientKdf {
        ClientKdf {
            _client: self.clone(),
        }
    }
}
