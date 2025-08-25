use bitwarden_api_api::models::UserDecryptionResponseModel;
use serde::{Deserialize, Serialize};

use crate::key_management::master_password::MasterPasswordError;
use crate::{
    auth::api::response::user_decryption_options_response::UserDecryptionOptionsResponseModel,
    key_management::master_password::MasterPasswordUnlockData,
};

/// Represents data required to decrypt user's vault.
/// Currently, this is only used for master password unlock.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UserDecryptionData {
    /// Optional master password unlock data.
    master_password_unlock: Option<MasterPasswordUnlockData>,
}

impl TryFrom<UserDecryptionResponseModel> for UserDecryptionData {
    type Error = MasterPasswordError;

    fn try_from(response: UserDecryptionResponseModel) -> Result<Self, Self::Error> {
        let master_password_unlock = response
            .master_password_unlock
            .map(|response| MasterPasswordUnlockData::try_from(*response))
            .transpose()?;

        Ok(UserDecryptionData {
            master_password_unlock,
        })
    }
}

impl TryFrom<UserDecryptionOptionsResponseModel> for UserDecryptionData {
    type Error = MasterPasswordError;

    fn try_from(response: UserDecryptionOptionsResponseModel) -> Result<Self, Self::Error> {
        let master_password_unlock = response
            .master_password_unlock
            .map(MasterPasswordUnlockData::try_from)
            .transpose()?;

        Ok(UserDecryptionData {
            master_password_unlock,
        })
    }
}
