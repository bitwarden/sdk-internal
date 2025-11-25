use bitwarden_api_api::models::MasterPasswordUnlockResponseModel;
use serde::{Deserialize, Serialize};

/// Provides user decryption options used to unlock user's vault.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct UserDecryptionOptionsResponse {
    /// Contains information needed to unlock user's vault with master password.
    /// None when user have no master password.
    #[serde(
        rename = "masterPasswordUnlock",
        alias = "MasterPasswordUnlock",
        skip_serializing_if = "Option::is_none"
    )]
    pub master_password_unlock: Option<MasterPasswordUnlockResponseModel>,
    // TODO: I have to build out all other unlock options here.

    // pub trusted_device_
}
