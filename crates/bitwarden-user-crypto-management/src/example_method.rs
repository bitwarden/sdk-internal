use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::key_connector_client::KeyConnectorClient;

#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum ExampleMethodError {
    #[error("Bitwarden API call failed")]
    ApiError,
    #[error("Key Connector API call failed")]
    KeyConnectorApiError,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl KeyConnectorClient {
    /// Combines a password change and user key rotation into a single request.
    pub async fn example_method(
        &self,
        key_connector_url: String,
    ) -> Result<(), ExampleMethodError> {
        let api_client = &self.api_configurations.api_client;

        // Used to be
        // let key_connector_api_client =
        // &self.client.internal.get_key_connector_client(key_connector_url);
        let key_connector_api_client = &self
            .api_configurations
            .get_key_connector_client(key_connector_url);

        return Ok(());
    }
}
