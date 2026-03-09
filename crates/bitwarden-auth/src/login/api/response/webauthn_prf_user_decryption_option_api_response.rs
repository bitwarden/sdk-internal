use bitwarden_crypto::{EncString, UnsignedSharedKey};
use serde::{Deserialize, Serialize};

/// WebAuthn PRF User Decryption Option API response.
/// Contains all required fields for WebAuthn PRF decryption.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct WebAuthnPrfUserDecryptionOptionApiResponse {
    /// PRF key encrypted private key
    #[serde(rename = "EncryptedPrivateKey")]
    pub encrypted_private_key: EncString,

    /// Public Key encrypted user key
    #[serde(rename = "EncryptedUserKey")]
    pub encrypted_user_key: UnsignedSharedKey,

    /// Credential ID for this WebAuthn PRF credential.
    /// TODO: PM-32163 - can remove `Option<T>` after 3 releases from server v2026.1.1
    #[serde(rename = "CredentialId")]
    pub credential_id: Option<String>,

    /// Transport methods available for this credential (e.g., "usb", "nfc", "ble", "internal",
    /// "hybrid").
    /// TODO: PM-32163 - can remove `Option<T>` after 3 releases from server v2026.1.1
    #[serde(rename = "Transports")]
    pub transports: Option<Vec<String>>,
}
