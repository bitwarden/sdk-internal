use serde::{Deserialize, Serialize};

/// Key Connector User Decryption Option API response.
/// Indicates that Key Connector is used for user decryption and
/// it contains all required fields for Key Connector decryption.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct KeyConnectorUserDecryptionOptionApiResponse {
    /// URL of the Key Connector server to use for decryption.
    #[serde(rename = "KeyConnectorUrl")]
    pub key_connector_url: String,
}
