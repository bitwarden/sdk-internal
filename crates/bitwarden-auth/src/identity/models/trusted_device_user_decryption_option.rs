use bitwarden_crypto::EncString;
use serde::{Deserialize, Serialize};

use crate::identity::api::response::TrustedDeviceUserDecryptionOptionApiResponse;

/// SDK domain model for Trusted Device user decryption option.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct TrustedDeviceUserDecryptionOption {
    /// Whether the user has admin approval for device login.
    pub has_admin_approval: bool,

    /// Whether the user has a device that can approve logins.
    pub has_login_approving_device: bool,

    /// Whether the user has permission to manage password reset for other users.
    pub has_manage_reset_password_permission: bool,

    /// Whether the user is in TDE offboarding.
    pub is_tde_offboarding: bool,

    /// The device key encrypted device private key. Only present if the device is trusted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_private_key: Option<EncString>,

    /// The device private key encrypted user key. Only present if the device is trusted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_user_key: Option<EncString>,
}

impl From<TrustedDeviceUserDecryptionOptionApiResponse> for TrustedDeviceUserDecryptionOption {
    fn from(api: TrustedDeviceUserDecryptionOptionApiResponse) -> Self {
        Self {
            has_admin_approval: api.has_admin_approval,
            has_login_approving_device: api.has_login_approving_device,
            has_manage_reset_password_permission: api.has_manage_reset_password_permission,
            is_tde_offboarding: api.is_tde_offboarding,
            encrypted_private_key: api.encrypted_private_key,
            encrypted_user_key: api.encrypted_user_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trusted_device_conversion() {
        let api = TrustedDeviceUserDecryptionOptionApiResponse {
            has_admin_approval: true,
            has_login_approving_device: false,
            has_manage_reset_password_permission: true,
            is_tde_offboarding: false,
            encrypted_private_key: Some("2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=".parse().unwrap()),
            encrypted_user_key: Some("2.kTtIypq9OLzd5iMMbU11pQ==|J4i3hTtGVdg7EZ+AQv/ujg==|QJpSpotQVpIW8j8dR/8l015WJzAIxBaOmrz4Uj/V1JA=".parse().unwrap()),
        };

        let domain: TrustedDeviceUserDecryptionOption = api.clone().into();

        assert_eq!(domain.has_admin_approval, api.has_admin_approval);
        assert_eq!(
            domain.has_login_approving_device,
            api.has_login_approving_device
        );
        assert_eq!(
            domain.has_manage_reset_password_permission,
            api.has_manage_reset_password_permission
        );
        assert_eq!(domain.is_tde_offboarding, api.is_tde_offboarding);
        assert_eq!(domain.encrypted_private_key, api.encrypted_private_key);
        assert_eq!(domain.encrypted_user_key, api.encrypted_user_key);
    }
}
