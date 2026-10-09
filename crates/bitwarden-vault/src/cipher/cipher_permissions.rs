use bitwarden_api_api::models::CipherPermissionsResponseModel;
use bitwarden_core::require;
use serde::{Deserialize, Serialize};

use crate::VaultParseError;

#[derive(Serialize, Copy, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct CipherPermissions {
    pub delete: bool,
    pub restore: bool,
}

impl TryFrom<CipherPermissionsResponseModel> for CipherPermissions {
    type Error = VaultParseError;

    fn try_from(permissions: CipherPermissionsResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            delete: require!(permissions.delete),
            restore: require!(permissions.restore),
        })
    }
}
