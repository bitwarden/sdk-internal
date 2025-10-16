use bitwarden_api_api::models::UserDecryptionResponseModel;
use serde::{Deserialize, Serialize};

use crate::{
    auth::UserDecryptionOptionsResponseModel,
    key_management::master_password::{MasterPasswordError, MasterPasswordUnlockData},
};

/// Represents data required to decrypt user's vault.
/// Currently, this is only used for master password unlock.
#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserDecryptionData {
    /// Optional master password unlock data.
    pub master_password_unlock: Option<MasterPasswordUnlockData>,
}

impl TryFrom<&UserDecryptionResponseModel> for UserDecryptionData {
    type Error = MasterPasswordError;

    fn try_from(response: &UserDecryptionResponseModel) -> Result<Self, Self::Error> {
        let master_password_unlock = response
            .master_password_unlock
            .as_deref()
            .map(MasterPasswordUnlockData::try_from)
            .transpose()?;

        Ok(UserDecryptionData {
            master_password_unlock,
        })
    }
}

impl TryFrom<&UserDecryptionOptionsResponseModel> for UserDecryptionData {
    type Error = MasterPasswordError;

    fn try_from(response: &UserDecryptionOptionsResponseModel) -> Result<Self, Self::Error> {
        let master_password_unlock = response
            .master_password_unlock
            .as_ref()
            .map(MasterPasswordUnlockData::try_from)
            .transpose()?;

        Ok(UserDecryptionData {
            master_password_unlock,
        })
    }
}
