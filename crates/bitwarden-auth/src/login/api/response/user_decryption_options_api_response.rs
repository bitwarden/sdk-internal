use bitwarden_api_api::models::MasterPasswordUnlockResponseModel;
use serde::{Deserialize, Serialize};

use crate::login::api::response::{
    KeyConnectorUserDecryptionOptionApiResponse, TrustedDeviceUserDecryptionOptionApiResponse,
    WebAuthnPrfUserDecryptionOptionApiResponse,
};

/// Provides user decryption options used to unlock user's vault.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub(crate) struct UserDecryptionOptionsApiResponse {
    /// Contains information needed to unlock user's vault with master password.
    /// None when user does not have a master password.
    #[serde(
        rename = "MasterPasswordUnlock",
        skip_serializing_if = "Option::is_none"
    )]
    pub master_password_unlock: Option<MasterPasswordUnlockResponseModel>,

    /// Trusted Device Decryption Option.
    #[serde(
        rename = "TrustedDeviceOption",
        skip_serializing_if = "Option::is_none"
    )]
    pub trusted_device_option: Option<TrustedDeviceUserDecryptionOptionApiResponse>,

    /// Key Connector Decryption Option.
    /// This option is mutually exlusive with the Trusted Device option as you
    /// must configure one or the other in the Organization SSO configuration.
    #[serde(rename = "KeyConnectorOption", skip_serializing_if = "Option::is_none")]
    pub key_connector_option: Option<KeyConnectorUserDecryptionOptionApiResponse>,

    /// WebAuthn PRF Decryption Option.
    #[serde(rename = "WebAuthnPrfOption", skip_serializing_if = "Option::is_none")]
    pub webauthn_prf_option: Option<WebAuthnPrfUserDecryptionOptionApiResponse>,
}
