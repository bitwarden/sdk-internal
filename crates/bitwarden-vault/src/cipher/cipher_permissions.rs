use bitwarden_api_api::models::CipherPermissionsResponseModel;
use bitwarden_core::require;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::VaultParseError;

#[derive(Serialize, Copy, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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
