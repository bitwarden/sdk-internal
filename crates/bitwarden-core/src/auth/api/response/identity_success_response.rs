use std::{collections::HashMap, num::NonZeroU32};

use bitwarden_api_identity::models::KdfType;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::api::response::user_decryption_options_response::UserDecryptionOptionsResponseModel;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub(crate) struct IdentityTokenSuccessResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    token_type: String,

    #[serde(rename = "privateKey", alias = "PrivateKey")]
    pub(crate) private_key: Option<String>,
    #[serde(alias = "Key")]
    pub(crate) key: Option<String>,
    #[serde(rename = "twoFactorToken")]
    two_factor_token: Option<String>,
    #[serde(alias = "Kdf")]
    kdf: KdfType,
    #[serde(rename = "kdfIterations", alias = "KdfIterations")]
    kdf_iterations: NonZeroU32,

    #[serde(rename = "resetMasterPassword", alias = "ResetMasterPassword")]
    pub reset_master_password: bool,
    #[serde(rename = "forcePasswordReset", alias = "ForcePasswordReset")]
    pub force_password_reset: bool,
    #[serde(rename = "apiUseKeyConnector", alias = "ApiUseKeyConnector")]
    api_use_key_connector: Option<bool>,
    #[serde(rename = "keyConnectorUrl", alias = "KeyConnectorUrl")]
    key_connector_url: Option<String>,

    #[serde(rename = "userDecryptionOptions", alias = "UserDecryptionOptions")]
    pub(crate) user_decryption_options: Option<UserDecryptionOptionsResponseModel>,

    /// Stores unknown api response fields
    extra: Option<HashMap<String, Value>>,
}

#[cfg(test)]
mod test {
    use bitwarden_crypto::Kdf;

    use super::*;

    impl Default for IdentityTokenSuccessResponse {
        fn default() -> Self {
            let Kdf::PBKDF2 { iterations } = Kdf::default_pbkdf2() else {
                panic!("Expected default KDF to be PBKDF2");
            };

            Self {
                access_token: Default::default(),
                expires_in: Default::default(),
                refresh_token: Default::default(),
                token_type: Default::default(),
                private_key: Default::default(),
                key: Default::default(),
                two_factor_token: Default::default(),
                kdf: KdfType::PBKDF2_SHA256,
                kdf_iterations: iterations,
                reset_master_password: Default::default(),
                force_password_reset: Default::default(),
                api_use_key_connector: Default::default(),
                key_connector_url: Default::default(),
                user_decryption_options: Default::default(),
                extra: Default::default(),
            }
        }
    }
}
