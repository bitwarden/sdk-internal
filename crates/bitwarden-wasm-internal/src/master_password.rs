#![allow(missing_docs)]

use bitwarden_api_api::models::KdfType;
use bitwarden_core::key_management::master_password::MasterPasswordUnlockData;
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
) -> Result<MasterPasswordUnlockData, JsValue> {
    let api_response: bitwarden_api_api::models::master_password_unlock_response_model::MasterPasswordUnlockResponseModel = response.into();

    MasterPasswordUnlockData::process_response(api_response)
        .map_err(|e| JsValue::from_str(&format!("MasterPasswordUnlockError: {}", e)))
}
