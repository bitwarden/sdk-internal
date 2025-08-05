#![allow(missing_docs)]

use bitwarden_api_api::models::KdfType;
use bitwarden_core::key_management::master_password::{
    MasterPasswordError, MasterPasswordUnlockData,
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

// WASM-compatible wrapper for the auto-generated MasterPasswordUnlockKdfResponseModel
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordUnlockKdfResponseModel {
    #[serde(alias = "KdfType")]
    pub kdf_type: KdfType,
    #[serde(alias = "Iterations")]
    pub iterations: i32,
    #[serde(alias = "Memory")]
    pub memory: Option<i32>,
    #[serde(alias = "Parallelism")]
    pub parallelism: Option<i32>,
}

// WASM-compatible wrapper for the auto-generated MasterPasswordUnlockResponseModel
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordUnlockResponseModel {
    #[serde(alias = "Kdf")]
    pub kdf: MasterPasswordUnlockKdfResponseModel,
    #[serde(alias = "MasterKeyEncryptedUserKey")]
    pub master_key_encrypted_user_key: Option<String>,
    #[serde(alias = "Salt")]
    pub salt: Option<String>,
}

impl From<MasterPasswordUnlockResponseModel> for bitwarden_api_api::models::master_password_unlock_response_model::MasterPasswordUnlockResponseModel {
    fn from(wasm_model: MasterPasswordUnlockResponseModel) -> Self {
        bitwarden_api_api::models::master_password_unlock_response_model::MasterPasswordUnlockResponseModel {
            kdf: Box::new(bitwarden_api_api::models::MasterPasswordUnlockKdfResponseModel {
                kdf_type: wasm_model.kdf.kdf_type,
                iterations: wasm_model.kdf.iterations,
                memory: wasm_model.kdf.memory,
                parallelism: wasm_model.kdf.parallelism,
            }),
            master_key_encrypted_user_key: wasm_model.master_key_encrypted_user_key,
            salt: wasm_model.salt,
        }
    }
}

/// WASM-exposed function to process a MasterPasswordUnlockResponse
#[wasm_bindgen]
pub fn process_master_password_unlock_response(
    response: MasterPasswordUnlockResponseModel,
) -> Result<MasterPasswordUnlockData, MasterPasswordError> {
    let api_response: bitwarden_api_api::models::master_password_unlock_response_model::MasterPasswordUnlockResponseModel = response.into();

    MasterPasswordUnlockData::process_response(api_response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_master_password_unlock_response_success_argon2() {
        let response = MasterPasswordUnlockResponseModel {
            kdf: MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::Argon2id,
                iterations: 3,
                memory: Some(64),
                parallelism: Some(4),
            },
            master_key_encrypted_user_key: Some("2.Dh7AFLXR+LXcxUaO5cRjpg==|uXyhubjAoNH8lTdy/zgJDQ==|cHEMboj0MYsU5yDRQ1rLCgxcjNbKRc1PWKuv8bpU5pM=".to_string()),
            salt: Some("test@example.com".to_string()),
        };

        let result = process_master_password_unlock_response(response);
        assert!(result.is_ok());
    }

    #[test]
    fn test_process_master_password_unlock_response_failure_missing_salt() {
        let response = MasterPasswordUnlockResponseModel {
            kdf: MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::Argon2id,
                iterations: 3,
                memory: Some(64),
                parallelism: Some(4),
            },
            master_key_encrypted_user_key: Some("2.Dh7AFLXR+LXcxUaO5cRjpg==|uXyhubjAoNH8lTdy/zgJDQ==|cHEMboj0MYsU5yDRQ1rLCgxcjNbKRc1PWKuv8bpU5pM=".to_string()),
            salt: None,
        };

        let result = process_master_password_unlock_response(response);
        assert!(result.is_err());
    }
}
