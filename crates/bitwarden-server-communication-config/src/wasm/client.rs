use wasm_bindgen::prelude::*;

use crate::{
    AcquiredCookie, ServerCommunicationConfig, ServerCommunicationConfigClient,
    SetCommunicationTypeRequest,
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

    /// Retrieves the server communication configuration for a domain
    ///
    /// If no configuration exists, returns a default Direct bootstrap configuration.
    ///
    /// # Arguments
    ///
    /// * `domain` - The server domain (e.g., "vault.acme.com")
    ///
    /// # Errors
    ///
    /// Returns an error if the repository fails to retrieve the configuration.
    #[wasm_bindgen(js_name = getConfig)]
    pub async fn get_config(&self, domain: String) -> Result<ServerCommunicationConfig, String> {
        self.client.get_config(domain).await
    }

    /// Determines if cookie bootstrapping is needed for this domain
    ///
    /// # Arguments
    ///
    /// * `domain` - The server domain (e.g., "vault.acme.com")
    #[wasm_bindgen(js_name = needsBootstrap)]
    pub async fn needs_bootstrap(&self, domain: String) -> bool {
        self.client.needs_bootstrap(domain).await
    }

    /// Returns all cookies that should be included in requests to this server
    ///
    /// Returns an array of [cookie_name, cookie_value] pairs.
    ///
    /// # Arguments
    ///
    /// * `domain` - The server domain (e.g., "vault.acme.com")
    #[wasm_bindgen(js_name = cookies)]
    #[deprecated(
        note = "Use get_cookies() instead, which will acquire cookies if not present in the config"
    )]
    #[allow(deprecated)]
    pub async fn cookies(&self, domain: String) -> Result<JsValue, JsError> {
        #[allow(deprecated)]
        let cookies = self.client.cookies(domain).await;
        serde_wasm_bindgen::to_value(&cookies).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Returns all cookies that should be included in requests to this server
    /// and triggers cookie acquisition if needed
    ///
    /// # Arguments
    ///
    /// * `domain` - The server domain (e.g., "vault.acme.com")
    #[wasm_bindgen(js_name = getCookies)]
    pub async fn get_cookies(&self, domain: String) -> Result<Vec<AcquiredCookie>, JsError> {
        let cookies = self.client.get_cookies(domain).await;
        cookies.map_err(|e| JsError::new(&e.to_string()))
    }

    /// Sets the server communication configuration for a domain
    ///
    /// This method saves the provided communication configuration to the repository.
    /// Typically called when receiving the `/api/config` response from the server.
    /// Previously acquired cookies are preserved automatically.
    ///
    /// # Arguments
    ///
    /// * `domain` - The server domain (e.g., "vault.acme.com")
    /// * `request` - The server communication configuration to store
    ///
    /// # Errors
    ///
    /// Returns an error if the repository save operation fails
    #[deprecated(
        note = "Use set_communication_type_v2() instead, which extracts the domain from the config"
    )]
    #[allow(deprecated)]
    #[wasm_bindgen(js_name = setCommunicationType)]
    pub async fn set_communication_type(
        &self,
        domain: String,
        request: SetCommunicationTypeRequest,
    ) -> Result<(), String> {
        #[allow(deprecated)]
        self.client.set_communication_type(domain, request).await
    }

    /// Sets the server communication configuration using the domain from the config
    ///
    /// Extracts the `cookie_domain` from the `SsoCookieVendor` config and uses it as the
    /// storage key. If the config is `Direct` or `cookie_domain` is not set, the call
    /// is silently ignored.
    ///
    /// # Arguments
    ///
    /// * `config` - The server communication configuration to store
    ///
    /// # Errors
    ///
    /// Returns an error if the repository save operation fails
    #[wasm_bindgen(js_name = setCommunicationTypeV2)]
    pub async fn set_communication_type_v2(
        &self,
        config: ServerCommunicationConfig,
    ) -> Result<(), String> {
        self.client.set_communication_type_v2(config).await
    }

    /// Acquires a cookie from the platform and saves it to the repository
    ///
    /// This method calls the platform API to trigger cookie acquisition (e.g., browser
    /// redirect to IdP), then validates and stores the acquired cookie in the repository.
    ///
    /// # Arguments
    ///
    /// * `domain` - The server domain (e.g., "vault.acme.com")
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Cookie acquisition was cancelled by the user
    /// - Server configuration doesn't support SSO cookies (Direct bootstrap)
    /// - Acquired cookie name doesn't match expected name
    /// - Repository operations fail
    #[wasm_bindgen(js_name = acquireCookie)]
    pub async fn acquire_cookie(&self, domain: String) -> Result<Vec<AcquiredCookie>, String> {
        self.client
            .acquire_cookie(&domain)
            .await
            .map_err(|e| e.to_string())
    }
}
