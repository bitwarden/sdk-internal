//! WebAuthn PRF unlock data. Each registered passkey that supports the PRF extension carries a
//! rotateable key set: a private key wrapped by the key derived from the credential's PRF output,
//! and the user key encapsulated to the matching public key. Unlocking derives the PRF key from the
//! authenticator, unwraps the private key, and decapsulates the user key with it.

use bitwarden_api_api::models::WebAuthnPrfDecryptionOption;
use bitwarden_crypto::{EncString, UnsignedSharedKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{MissingFieldError, require};

/// The unlock data for a single WebAuthn PRF credential.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct WebAuthnPrfUnlockOption {
    /// The private key of the unlock option, wrapped by the key derived from the credential's PRF
    /// output
    pub encrypted_private_key: EncString,
    /// The user key, encapsulated with the public key of the unlock option
    pub encrypted_user_key: UnsignedSharedKey,
    /// Credential ID for this WebAuthn PRF credential.
    pub credential_id: Option<String>,
    /// Transport methods available for this credential (e.g., "usb", "nfc", "ble", "internal",
    /// "hybrid").
    pub transports: Option<Vec<String>>,
}

/// Every WebAuthn PRF credential the account can unlock with.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct WebAuthnPrfUnlockData {
    /// The credentials, in the order the server reported them.
    pub options: Vec<WebAuthnPrfUnlockOption>,
}

#[cfg(feature = "wasm")]
impl TryFrom<wasm_bindgen::JsValue> for WebAuthnPrfUnlockData {
    type Error = serde_wasm_bindgen::Error;

    fn try_from(value: wasm_bindgen::JsValue) -> Result<Self, Self::Error> {
        serde_wasm_bindgen::from_value(value)
    }
}

impl TryFrom<&WebAuthnPrfDecryptionOption> for WebAuthnPrfUnlockOption {
    type Error = WebAuthnPrfError;

    fn try_from(response: &WebAuthnPrfDecryptionOption) -> Result<Self, Self::Error> {
        let encrypted_private_key = require!(&response.encrypted_private_key)
            .parse()
            .map_err(|_| WebAuthnPrfError::ResponseModelMalformed)?;
        let encrypted_user_key = require!(&response.encrypted_user_key)
            .parse()
            .map_err(|_| WebAuthnPrfError::ResponseModelMalformed)?;

        Ok(WebAuthnPrfUnlockOption {
            encrypted_private_key,
            encrypted_user_key,
            credential_id: response.credential_id.clone(),
            transports: response.transports.clone(),
        })
    }
}

/// Errors that can occur when working with WebAuthn PRF unlock data
#[derive(Debug, Error)]
pub enum WebAuthnPrfError {
    /// A key field is present but could not be parsed
    #[error("Response model malformed")]
    ResponseModelMalformed,
    /// A required key field is missing
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENCRYPTED_PRIVATE_KEY: &str = "2.fkvl0+sL1lwtiOn1eewsvQ==|dT0TynLl8YERZ8x7dxC+DQ==|cWhiRSYHOi/AA2LiV/JBJWbO9C7pbUpOM6TMAcV47hE=";
    const ENCRYPTED_USER_KEY: &str = "4.DMD1D5r6BsDDd7C/FE1eZbMCKrmryvAsCKj6+bO54gJNUxisOI7SDcpPLRXf+JdhqY15pT+wimQ5cD9C+6OQ6s71LFQHewXPU29l9Pa1JxGeiKqp37KLYf+1IS6UB2K3ANN35C52ZUHh2TlzIS5RuntxnpCw7APbcfpcnmIdLPJBtuj/xbFd6eBwnI3GSe5qdS6/Ixdd0dgsZcpz3gHJBKmIlSo0YN60SweDq3kTJwox9xSqdCueIDg5U4khc7RhjYx8b33HXaNJj3DwgIH8iLj+lqpDekogr630OhHG3XRpvl4QzYO45bmHb8wAh67Dj70nsZcVg6bAEFHdSFohww==";

    fn build_response_model() -> WebAuthnPrfDecryptionOption {
        WebAuthnPrfDecryptionOption {
            encrypted_private_key: Some(ENCRYPTED_PRIVATE_KEY.to_string()),
            encrypted_user_key: Some(ENCRYPTED_USER_KEY.to_string()),
            credential_id: None,
            transports: None,
        }
    }

    #[test]
    fn test_from_response_model() {
        let response = build_response_model();

        let option = WebAuthnPrfUnlockOption::try_from(&response).unwrap();

        assert_eq!(
            option.encrypted_private_key,
            ENCRYPTED_PRIVATE_KEY.parse().unwrap()
        );
        assert_eq!(
            option.encrypted_user_key.to_string(),
            ENCRYPTED_USER_KEY.to_string()
        );
        assert_eq!(option.credential_id, None);
        assert_eq!(option.transports, None);
    }

    #[test]
    fn test_from_response_model_with_optional_fields() {
        let mut response = build_response_model();
        response.credential_id = Some("test-credential-id".to_string());
        response.transports = Some(vec!["usb".to_string(), "nfc".to_string()]);

        let option = WebAuthnPrfUnlockOption::try_from(&response).unwrap();

        assert_eq!(option.credential_id, Some("test-credential-id".to_string()));
        assert_eq!(
            option.transports,
            Some(vec!["usb".to_string(), "nfc".to_string()])
        );
    }

    #[test]
    fn test_from_response_model_missing_encrypted_private_key() {
        let mut response = build_response_model();
        response.encrypted_private_key = None;

        assert!(matches!(
            WebAuthnPrfUnlockOption::try_from(&response),
            Err(WebAuthnPrfError::MissingField(_))
        ));
    }

    #[test]
    fn test_from_response_model_missing_encrypted_user_key() {
        let mut response = build_response_model();
        response.encrypted_user_key = None;

        assert!(matches!(
            WebAuthnPrfUnlockOption::try_from(&response),
            Err(WebAuthnPrfError::MissingField(_))
        ));
    }

    #[test]
    fn test_from_response_model_unparseable_encrypted_user_key() {
        let mut response = build_response_model();
        response.encrypted_user_key = Some("not an unsigned shared key".to_string());

        assert!(matches!(
            WebAuthnPrfUnlockOption::try_from(&response),
            Err(WebAuthnPrfError::ResponseModelMalformed)
        ));
    }

    #[test]
    fn test_unlock_data_serde_round_trip() {
        let data = WebAuthnPrfUnlockData {
            options: vec![WebAuthnPrfUnlockOption::try_from(&build_response_model()).unwrap()],
        };

        let serialized = serde_json::to_string(&data).unwrap();
        let deserialized: WebAuthnPrfUnlockData = serde_json::from_str(&serialized).unwrap();

        assert_eq!(data, deserialized);
    }
}
