use bitwarden_crypto::{CryptoError, EncString, HashPurpose, Kdf, MasterKey, RsaKeyPair};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ApiError;

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterRequest {
    pub email: String,
    pub name: Option<String>,
    pub password: String,
    pub password_hint: Option<String>,
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum RegisterError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Api(#[from] ApiError),
}

pub(super) fn make_register_keys(
    email: String,
    password: String,
    kdf: Kdf,
) -> Result<RegisterKeyResponse, CryptoError> {
    let master_key = MasterKey::derive(&password, &email, &kdf)?;
    let master_password_hash =
        master_key.derive_master_key_hash(password.as_bytes(), HashPurpose::ServerAuthorization)?;
    let (user_key, encrypted_user_key) = master_key.make_user_key()?;
    let keys = user_key.make_key_pair()?;

    Ok(RegisterKeyResponse {
        master_password_hash,
        encrypted_user_key,
        keys,
    })
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RegisterKeyResponse {
    pub master_password_hash: String,
    pub encrypted_user_key: EncString,
    pub keys: RsaKeyPair,
}
