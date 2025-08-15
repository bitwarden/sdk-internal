use bitwarden_api_api::models::MasterPasswordUnlockResponseModel;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct UserDecryptionOptionsResponseModel {
    #[serde(
        rename = "masterPasswordUnlock",
        skip_serializing_if = "Option::is_none"
    )]
    pub master_password_unlock: Option<MasterPasswordUnlockResponseModel>,
}
