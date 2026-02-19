use wasm_bindgen::prelude::*;

use crate::{
    CookieProvider, ServerCommunicationConfig, ServerCommunicationConfigClient,
    wasm::{
        JsServerCommunicationConfigPlatformApi, JsServerCommunicationConfigRepository,
        RawJsServerCommunicationConfigPlatformApi, RawJsServerCommunicationConfigRepository,
    },
};

/// JavaScript wrapper for ServerCommunicationConfigClient
///
/// This provides TypeScript access to the server communication configuration client,
/// allowing clients to check bootstrap requirements and retrieve cookies for HTTP requests.
#[wasm_bindgen(js_name = ServerCommunicationConfigClient)]
pub struct JsServerCommunicationConfigClient {
    client: ServerCommunicationConfigClient<
        JsServerCommunicationConfigRepository,
        JsServerCommunicationConfigPlatformApi,
    >,
}

#[wasm_bindgen(js_class = ServerCommunicationConfigClient)]
impl JsServerCommunicationConfigClient {
    /// Creates a new ServerCommunicationConfigClient with a JavaScript repository and platform API
    ///
    /// The repository should be backed by StateProvider (or equivalent
    /// storage mechanism) for persistence.
    ///
    /// # Arguments
    ///
    /// * `repository` - JavaScript implementation of the repository interface
    /// * `platform_api` - JavaScript implementation of the platform API interface
    #[wasm_bindgen(constructor)]
    pub fn new(
        repository: RawJsServerCommunicationConfigRepository,
        platform_api: RawJsServerCommunicationConfigPlatformApi,
    ) -> Self {
        let js_repository = JsServerCommunicationConfigRepository::new(repository);
        let js_platform_api = JsServerCommunicationConfigPlatformApi::new(platform_api);
        Self {
            client: ServerCommunicationConfigClient::new(js_repository, js_platform_api),
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

    /// Acquires a cookie from the platform and saves it to the repository
    ///
    /// This method calls the platform API to trigger cookie acquisition (e.g., browser
    /// redirect to IdP), then validates and stores the acquired cookie in the repository.
    ///
    /// # Arguments
    ///
    /// * `hostname` - The server hostname (e.g., "vault.acme.com")
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Cookie acquisition was cancelled by the user
    /// - Server configuration doesn't support SSO cookies (Direct bootstrap)
    /// - Acquired cookie name doesn't match expected name
    /// - Repository operations fail
    #[wasm_bindgen(js_name = acquireCookie)]
    pub async fn acquire_cookie(&self, hostname: String) -> Result<(), String> {
        self.client
            .acquire_cookie(&hostname)
            .await
            .map_err(|e| e.to_string())
    }
}

/// CookieProvider implementation for WASM wrapper
///
/// Enables JsServerCommunicationConfigClient to be used as a cookie provider
/// for HTTP middleware without exposing the inner generic client type.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl CookieProvider for JsServerCommunicationConfigClient {
    async fn cookies(&self, hostname: String) -> Vec<(String, String)> {
        self.client.cookies(hostname).await
    }

    async fn acquire_cookie(
        &self,
        hostname: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.client
            .acquire_cookie(hostname)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
}
