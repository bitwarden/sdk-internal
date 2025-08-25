use bitwarden_api_api::models::MasterPasswordUnlockResponseModel;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub(crate) struct IdentityUserDecryptionOptionsResponseModel {
    #[serde(
        rename = "masterPasswordUnlock",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) master_password_unlock: Option<MasterPasswordUnlockResponseModel>,
}
