use bitwarden_crypto::EncString;
use serde::{Deserialize, Serialize};

/// WebAuthn PRF User Decryption Option API response.
/// Contains all required fields for WebAuthn PRF decryption.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct WebAuthnPrfUserDecryptionOptionApiResponse {
    /// PRF key encrypted private key
    #[serde(rename = "EncryptedPrivateKey")]
    pub encrypted_private_key: EncString,

    /// Private Key encrypted user key
    #[serde(rename = "EncryptedUserKey")]
    pub encrypted_user_key: EncString,
}
