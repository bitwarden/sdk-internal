use serde::{Deserialize, Serialize};

use crate::identity::api::response::KeyConnectorUserDecryptionOptionApiResponse;

/// SDK domain model for Key Connector user decryption option.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct KeyConnectorUserDecryptionOption {
    /// URL of the Key Connector server to use for decryption.
    pub key_connector_url: String,
}

impl From<KeyConnectorUserDecryptionOptionApiResponse> for KeyConnectorUserDecryptionOption {
    fn from(api: KeyConnectorUserDecryptionOptionApiResponse) -> Self {
        Self {
            key_connector_url: api.key_connector_url,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_connector_conversion() {
        let api = KeyConnectorUserDecryptionOptionApiResponse {
            key_connector_url: "https://key-connector.example.com".to_string(),
        };

        let domain: KeyConnectorUserDecryptionOption = api.clone().into();

        assert_eq!(domain.key_connector_url, api.key_connector_url);
    }
}
