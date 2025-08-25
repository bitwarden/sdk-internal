use bitwarden_api_api::models::UserDecryptionResponseModel;
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};

use crate::{
    auth::api::response::identity_user_decryption_options_response::IdentityUserDecryptionOptionsResponseModel,
    key_management::master_password::{MasterPasswordError, MasterPasswordUnlockData},
};

/// Error for master user decryption related operations.
#[bitwarden_error(flat)]
#[derive(Debug, thiserror::Error)]
enum UserDecryptionError {
    /// Error related to master password unlock.
    #[error(transparent)]
    MasterPasswordError(#[from] MasterPasswordError),
}

/// Represents data required to decrypt user's vault.
/// Currently, this is only used for master password unlock.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UserDecryptionData {
    /// Optional master password unlock data.
    master_password_unlock: Option<MasterPasswordUnlockData>,
}

impl TryFrom<UserDecryptionResponseModel> for UserDecryptionData {
    type Error = UserDecryptionError;

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

impl TryFrom<IdentityUserDecryptionOptionsResponseModel> for UserDecryptionData {
    type Error = UserDecryptionError;

    fn try_from(response: IdentityUserDecryptionOptionsResponseModel) -> Result<Self, Self::Error> {
        let master_password_unlock = response
            .master_password_unlock
            .map(MasterPasswordUnlockData::try_from)
            .transpose()?;

        Ok(UserDecryptionData {
            master_password_unlock,
        })
    }
}
