use bitwarden_crypto::EncString;
use serde::{Deserialize, Serialize};

use crate::identity::api::response::WebAuthnPrfUserDecryptionOptionApiResponse;

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

    /// Private Key encrypted user key
    pub encrypted_user_key: EncString,
}

impl From<WebAuthnPrfUserDecryptionOptionApiResponse> for WebAuthnPrfUserDecryptionOption {
    fn from(api: WebAuthnPrfUserDecryptionOptionApiResponse) -> Self {
        Self {
            encrypted_private_key: api.encrypted_private_key,
            encrypted_user_key: api.encrypted_user_key,
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
            encrypted_user_key: "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=".parse().unwrap(),
        };

        let domain: WebAuthnPrfUserDecryptionOption = api.clone().into();

        assert_eq!(domain.encrypted_private_key, api.encrypted_private_key);
        assert_eq!(domain.encrypted_user_key, api.encrypted_user_key);
    }
}
