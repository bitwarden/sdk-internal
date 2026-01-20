use std::sync::Arc;

use wasm_bindgen::prelude::*;

use crate::{
    ServerCommunicationConfig, ServerCommunicationConfigClient,
    wasm::{JsServerCommunicationConfigRepository, RawJsServerCommunicationConfigRepository},
};

/// JavaScript wrapper for ServerCommunicationConfigClient
///
/// This provides TypeScript access to the server communication configuration client,
/// allowing clients to check bootstrap requirements and retrieve cookies for HTTP requests.
#[wasm_bindgen(js_name = ServerCommunicationConfigClient)]
pub struct JsServerCommunicationConfigClient {
    client: ServerCommunicationConfigClient<JsServerCommunicationConfigRepository>,
}

#[wasm_bindgen(js_class = ServerCommunicationConfigClient)]
impl JsServerCommunicationConfigClient {
    /// Creates a new ServerCommunicationConfigClient with a JavaScript repository
    ///
    /// The repository should be backed by the State Provider for persistence.
    ///
    /// # Arguments
    ///
    /// * `repository` - JavaScript implementation of the repository interface
    #[wasm_bindgen(constructor)]
    pub fn new(repository: RawJsServerCommunicationConfigRepository) -> Self {
        let js_repository = JsServerCommunicationConfigRepository::new(repository);
        Self {
            client: ServerCommunicationConfigClient::new(Arc::new(js_repository)),
        }
    }

    /// Retrieves the server communication configuration for a hostname
    ///
    /// If no configuration exists, returns a default Direct bootstrap configuration.
    ///
    /// # Arguments
    ///
    /// * `hostname` - The server hostname (e.g., "vault.acme.com")
    ///
    /// # Errors
    ///
    /// Returns an error if the repository fails to retrieve the configuration.
    #[wasm_bindgen(js_name = getConfig)]
    pub async fn get_config(&self, hostname: String) -> Result<ServerCommunicationConfig, String> {
        self.client.get_config(hostname).await
    }

    /// Determines if cookie bootstrapping is needed for this hostname
    ///
    /// Always returns `false` in WASM environments since Browser/Web clients
    /// share the browser's cookie store.
    ///
    /// # Arguments
    ///
    /// * `hostname` - The server hostname (e.g., "vault.acme.com")
    #[wasm_bindgen(js_name = needsBootstrap)]
    pub async fn needs_bootstrap(&self, hostname: String) -> bool {
        self.client.needs_bootstrap(hostname).await
    }

    /// Returns all cookies that should be included in requests to this server
    ///
    /// Returns an array of [cookie_name, cookie_value] pairs.
    ///
    /// # Arguments
    ///
    /// * `hostname` - The server hostname (e.g., "vault.acme.com")
    #[wasm_bindgen(js_name = cookies)]
    pub async fn cookies(&self, hostname: String) -> Result<JsValue, JsError> {
        let cookies = self.client.cookies(hostname).await;
        serde_wasm_bindgen::to_value(&cookies).map_err(|e| JsError::new(&e.to_string()))
    }
}
