use bitwarden_api_api::models::{MasterPasswordUnlockResponseModel, UserDecryptionResponseModel};
use bitwarden_core::key_management::{
    master_password::{MasterPasswordError, MasterPasswordUnlockData},
    user_decryption::{UserDecryptionData, UserDecryptionError},
};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub struct UserDecryption {}

#[wasm_bindgen]
impl UserDecryption {
    pub fn get_user_decryption_data(
        response: UserDecryptionResponseModel,
    ) -> Result<UserDecryptionData, UserDecryptionError> {
        UserDecryptionData::try_from(response)
    }

    pub fn get_master_password_unlock_data(
        response: MasterPasswordUnlockResponseModel,
    ) -> Result<MasterPasswordUnlockData, MasterPasswordError> {
        MasterPasswordUnlockData::try_from(response)
    }
}
