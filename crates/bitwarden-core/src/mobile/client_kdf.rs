use bitwarden_crypto::{CryptoError, HashPurpose, Kdf};

use crate::{error::Result, mobile::kdf::hash_password, Client};

pub struct ClientKdf<'a> {
    pub(crate) _client: &'a crate::Client,
}

impl ClientKdf<'_> {
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

impl<'a> Client {
    pub fn kdf(&'a self) -> ClientKdf<'a> {
        ClientKdf { _client: self }
    }
}
