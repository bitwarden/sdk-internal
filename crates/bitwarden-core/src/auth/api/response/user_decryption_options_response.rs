use bitwarden_api_api::models::MasterPasswordUnlockResponseModel;
use serde::{Deserialize, Serialize};

/// Provides user decryption options used to unlock user's vault.
/// Currently, only master password unlock is supported.
#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub(crate) struct UserDecryptionOptionsResponseModel {
    /// Contains information needed to unlock user's vault with master password.
    /// None when user have no master password.
    #[serde(
        rename = "masterPasswordUnlock",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) master_password_unlock: Option<MasterPasswordUnlockResponseModel>,
}
