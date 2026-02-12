use bitwarden_crypto::{EncString, UnsignedSharedKey};
use serde::{Deserialize, Serialize};

use crate::login::api::response::WebAuthnPrfUserDecryptionOptionApiResponse;

/// SDK domain model for WebAuthn PRF user decryption option.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct WebAuthnPrfUserDecryptionOption {
    /// PRF key encrypted private key
    pub encrypted_private_key: EncString,

    /// Public Key encrypted user key
    pub encrypted_user_key: UnsignedSharedKey,

    /// Credential ID for this WebAuthn PRF credential.
    /// TODO: PM-32163 - can remove Option<T> after 3 releases from server v2026.1.1
    pub credential_id: Option<String>,

    /// Transport methods available for this credential (e.g., "usb", "nfc", "ble", "internal",
    /// "hybrid").
    /// TODO: PM-32163 - can remove Option<T> after 3 releases from server v2026.1.1
    pub transports: Option<Vec<String>>,
}

impl From<WebAuthnPrfUserDecryptionOptionApiResponse> for WebAuthnPrfUserDecryptionOption {
    fn from(api: WebAuthnPrfUserDecryptionOptionApiResponse) -> Self {
        Self {
            encrypted_private_key: api.encrypted_private_key,
            encrypted_user_key: api.encrypted_user_key,
            credential_id: api.credential_id,
            transports: api.transports,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webauthn_prf_conversion() {
        let api = WebAuthnPrfUserDecryptionOptionApiResponse {
            encrypted_private_key: "2.fkvl0+sL1lwtiOn1eewsvQ==|dT0TynLl8YERZ8x7dxC+DQ==|cWhiRSYHOi/AA2LiV/JBJWbO9C7pbUpOM6TMAcV47hE=".parse().unwrap(),
            encrypted_user_key: "4.DMD1D5r6BsDDd7C/FE1eZbMCKrmryvAsCKj6+bO54gJNUxisOI7SDcpPLRXf+JdhqY15pT+wimQ5cD9C+6OQ6s71LFQHewXPU29l9Pa1JxGeiKqp37KLYf+1IS6UB2K3ANN35C52ZUHh2TlzIS5RuntxnpCw7APbcfpcnmIdLPJBtuj/xbFd6eBwnI3GSe5qdS6/Ixdd0dgsZcpz3gHJBKmIlSo0YN60SweDq3kTJwox9xSqdCueIDg5U4khc7RhjYx8b33HXaNJj3DwgIH8iLj+lqpDekogr630OhHG3XRpvl4QzYO45bmHb8wAh67Dj70nsZcVg6bAEFHdSFohww==".parse().unwrap(),
            credential_id: None,
            transports: None,
        };

        let domain: WebAuthnPrfUserDecryptionOption = api.clone().into();

        assert_eq!(domain.encrypted_private_key, api.encrypted_private_key);
        assert_eq!(domain.encrypted_user_key, api.encrypted_user_key);
        assert_eq!(domain.credential_id, None);
        assert_eq!(domain.transports, None);
    }

    #[test]
    fn test_webauthn_prf_conversion_with_optional_fields() {
        let api = WebAuthnPrfUserDecryptionOptionApiResponse {
            encrypted_private_key: "2.fkvl0+sL1lwtiOn1eewsvQ==|dT0TynLl8YERZ8x7dxC+DQ==|cWhiRSYHOi/AA2LiV/JBJWbO9C7pbUpOM6TMAcV47hE=".parse().unwrap(),
            encrypted_user_key: "4.DMD1D5r6BsDDd7C/FE1eZbMCKrmryvAsCKj6+bO54gJNUxisOI7SDcpPLRXf+JdhqY15pT+wimQ5cD9C+6OQ6s71LFQHewXPU29l9Pa1JxGeiKqp37KLYf+1IS6UB2K3ANN35C52ZUHh2TlzIS5RuntxnpCw7APbcfpcnmIdLPJBtuj/xbFd6eBwnI3GSe5qdS6/Ixdd0dgsZcpz3gHJBKmIlSo0YN60SweDq3kTJwox9xSqdCueIDg5U4khc7RhjYx8b33HXaNJj3DwgIH8iLj+lqpDekogr630OhHG3XRpvl4QzYO45bmHb8wAh67Dj70nsZcVg6bAEFHdSFohww==".parse().unwrap(),
            credential_id: Some("test-credential-id".to_string()),
            transports: Some(vec!["usb".to_string(), "nfc".to_string()]),
        };

        let domain: WebAuthnPrfUserDecryptionOption = api.clone().into();

        assert_eq!(domain.encrypted_private_key, api.encrypted_private_key);
        assert_eq!(domain.encrypted_user_key, api.encrypted_user_key);
        assert_eq!(domain.credential_id, Some("test-credential-id".to_string()));
        assert_eq!(
            domain.transports,
            Some(vec!["usb".to_string(), "nfc".to_string()])
        );
    }
}
