use bitwarden_crypto::EncString;
use serde::{Deserialize, Serialize};

/// Trusted Device User Decryption Option API response.
/// Contains settings and encrypted keys for trusted device decryption.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct TrustedDeviceUserDecryptionOptionApiResponse {
    /// Whether the user has admin approval for device login.
    #[serde(rename = "HasAdminApproval")]
    pub has_admin_approval: bool,

    /// Whether the user has a device that can approve logins.
    #[serde(rename = "HasLoginApprovingDevice")]
    pub has_login_approving_device: bool,

    /// Whether the user has permission to manage password reset for other users.
    #[serde(rename = "HasManageResetPasswordPermission")]
    pub has_manage_reset_password_permission: bool,

    /// Whether the user is in TDE offboarding.
    #[serde(rename = "IsTdeOffboarding")]
    pub is_tde_offboarding: bool,

    /// The device key encrypted device private key. Only present if the device is trusted.
    #[serde(
        rename = "EncryptedPrivateKey",
        skip_serializing_if = "Option::is_none"
    )]
    pub encrypted_private_key: Option<EncString>,

    /// The device private key encrypted user key. Only present if the device is trusted.
    #[serde(rename = "EncryptedUserKey", skip_serializing_if = "Option::is_none")]
    pub encrypted_user_key: Option<EncString>,
}
