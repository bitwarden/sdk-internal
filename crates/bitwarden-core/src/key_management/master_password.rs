#![allow(missing_docs)]

use crate::{require, MissingFieldError};
use bitwarden_api_api::models::master_password_unlock_response_model::MasterPasswordUnlockResponseModel;
use bitwarden_api_api::models::KdfType;
use bitwarden_crypto::{CryptoError, EncString, Kdf};
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use std::str::FromStr;

#[bitwarden_error(flat)]
#[derive(Debug, thiserror::Error)]
pub enum MasterPasswordError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct MasterPasswordUnlockData {
    pub kdf: Kdf,
    pub master_key_wrapped_user_key: EncString,
    pub salt: String,
}

impl MasterPasswordUnlockData {
    pub fn process_response(
        response: MasterPasswordUnlockResponseModel,
    ) -> Result<MasterPasswordUnlockData, MasterPasswordError> {
        let kdf = match response.kdf.kdf_type {
            KdfType::PBKDF2_SHA256 => Kdf::PBKDF2 {
                iterations: NonZeroU32::new(response.kdf.iterations as u32).unwrap(),
            },
            KdfType::Argon2id => Kdf::Argon2id {
                iterations: NonZeroU32::new(response.kdf.iterations as u32).unwrap(),
                memory: NonZeroU32::new(require!(response.kdf.memory) as u32).unwrap(),
                parallelism: NonZeroU32::new(require!(response.kdf.parallelism) as u32).unwrap(),
            },
        };

        let master_key_encrypted_user_key = require!(response.master_key_encrypted_user_key);
        let master_key_wrapped_user_key =
            EncString::from_str(master_key_encrypted_user_key.as_str())
                .map_err(|e: CryptoError| MasterPasswordError::from(e))?;

        let salt = require!(response.salt);

        Ok(MasterPasswordUnlockData {
            kdf,
            master_key_wrapped_user_key,
            salt,
        })
    }
}

#[allow(missing_docs)]
#[cfg(test)]
mod test {
    // TODO
}
