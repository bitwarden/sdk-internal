use std::sync::{Arc, OnceLock, RwLock};

use bitwarden_crypto::KeyStore;
use bitwarden_state::registry::StateRegistry;
use reqwest::header::{self, HeaderValue};

#[cfg(feature = "internal")]
use crate::client::flags::Flags;
use crate::{
    auth::auth_tokens::{NoopTokenHandler, TokenHandler},
    client::{
        client::Client,
        client_settings::{ClientName, ClientSettings},
        internal::{ApiConfigurations, InternalClient},
    },
};

/// Builder for constructing [`Client`] instances with custom configuration.
pub struct ClientBuilder {
    settings: Option<ClientSettings>,
    token_handler: Arc<dyn TokenHandler>,
    state_registry: Option<StateRegistry>,
}

impl ClientBuilder {
    /// Creates a new [`ClientBuilder`] with default settings.
    pub fn new() -> Self {
        Self {
            settings: None,
            token_handler: Arc::new(NoopTokenHandler),
            state_registry: None,
        }
    }

    /// Sets the [`ClientSettings`] for the client being built.
    pub fn with_settings(mut self, settings: ClientSettings) -> Self {
        self.settings = Some(settings);
        self
    }

    /// Sets a custom [`TokenHandler`] for managing authentication tokens.
    pub fn with_token_handler(mut self, token_handler: Arc<dyn TokenHandler>) -> Self {
        self.token_handler = token_handler;
        self
    }

    /// Sets a custom [`StateRegistry`] for the client being built.
    /// If not set, defaults to [`StateRegistry::new_with_memory_db`].
    pub fn with_state(mut self, state_registry: StateRegistry) -> Self {
        self.state_registry = Some(state_registry);
        self
    }

    /// Consumes the builder and constructs a [`Client`].
    pub fn build(self) -> Client {
        let settings = self.settings.unwrap_or_default();

        let external_http_client = new_http_client_builder()
            .build()
            .expect("External HTTP Client build should not fail");

        let headers = build_default_headers(&settings);

        let login_method = Arc::new(RwLock::new(None));
        let key_store = KeyStore::default();

        // Create the HTTP client for the Identity service, without authentication middleware.
        let bw_http_client = new_http_client_builder()
            .default_headers(headers)
            .build()
            .expect("Bw HTTP Client build should not fail");
        let identity = bitwarden_api_identity::Configuration {
            base_path: settings.identity_url,
            client: bw_http_client.clone().into(),
        };

        // Create the client for the API service, with authentication middleware.
        let auth_middleware = self.token_handler.initialize_middleware(
            login_method.clone(),
            identity.clone(),
            key_store.clone(),
        );
        let bw_http_client = reqwest_middleware::ClientBuilder::new(bw_http_client)
            .with_arc(auth_middleware)
            .build();
        let api = bitwarden_api_api::Configuration {
            base_path: settings.api_url,
            client: bw_http_client,
        };

        Client {
            internal: Arc::new(InternalClient {
                user_id: OnceLock::new(),
                token_handler: self.token_handler,
                login_method,
                #[cfg(feature = "internal")]
                flags: RwLock::new(Flags::default()),
                api_configurations: ApiConfigurations::new(identity, api, settings.device_type),
                external_http_client,
                key_store,
                #[cfg(feature = "internal")]
                security_state: RwLock::new(None),
                state_registry: self.state_registry.unwrap_or_else(StateRegistry::new_with_memory_db),
            }),
        }
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn new_http_client_builder() -> reqwest::ClientBuilder {
    #[allow(unused_mut)]
    let mut client_builder = reqwest::Client::builder();

    #[cfg(not(target_arch = "wasm32"))]
    {
        use rustls::ClientConfig;
        use rustls_platform_verifier::ConfigVerifierExt;
        client_builder = client_builder.use_preconfigured_tls(
            ClientConfig::with_platform_verifier().expect("Failed to create platform verifier"),
        );

        // Enforce HTTPS for all requests in non-debug builds
        #[cfg(not(debug_assertions))]
        {
            client_builder = client_builder.https_only(true);
        }
    }

    client_builder
}

/// Build default headers for Bitwarden HttpClient
fn build_default_headers(settings: &ClientSettings) -> header::HeaderMap {
    let mut headers = header::HeaderMap::new();

    // Handle optional headers

    if let Some(device_identifier) = &settings.device_identifier {
        headers.append(
            "Device-Identifier",
            HeaderValue::from_str(device_identifier)
                .expect("Device identifier should be a valid header value"),
        );
    }

    if let Some(client_type) = Into::<Option<ClientName>>::into(settings.device_type) {
        headers.append(
            "Bitwarden-Client-Name",
            HeaderValue::from_str(&client_type.to_string())
                .expect("All ASCII strings are valid header values"),
        );
    }

    if let Some(version) = &settings.bitwarden_client_version {
        headers.append(
            "Bitwarden-Client-Version",
            HeaderValue::from_str(version).expect("Version should be a valid header value"),
        );
    }

    if let Some(package_type) = &settings.bitwarden_package_type {
        headers.append(
            "Bitwarden-Package-Type",
            HeaderValue::from_str(package_type)
                .expect("Package type should be a valid header value"),
        );
    }

    // Handle required headers

    headers.append(
        "Device-Type",
        HeaderValue::from_str(&(settings.device_type as u8).to_string())
            .expect("All numbers are valid ASCII"),
    );

    headers.append(
        reqwest::header::USER_AGENT,
        HeaderValue::from_str(&settings.user_agent)
            .expect("User agent should be a valid header value"),
    );

    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_builder_default_builds() {
        let _client = ClientBuilder::new().build();
    }

    #[test]
    fn test_client_builder_with_settings_builds() {
        let settings = ClientSettings::default();
        let _client = ClientBuilder::new().with_settings(settings).build();
    }

    #[test]
    fn test_client_builder_with_token_handler_builds() {
        let handler: Arc<dyn TokenHandler> = Arc::new(NoopTokenHandler);
        let _client = ClientBuilder::new().with_token_handler(handler).build();
    }

    #[test]
    fn test_client_builder_chain_order_independence() {
        let _a = ClientBuilder::new()
            .with_settings(ClientSettings::default())
            .with_token_handler(Arc::new(NoopTokenHandler) as Arc<dyn TokenHandler>)
            .build();
        let _b = ClientBuilder::new()
            .with_token_handler(Arc::new(NoopTokenHandler) as Arc<dyn TokenHandler>)
            .with_settings(ClientSettings::default())
            .build();
    }

    #[test]
    fn test_client_builder_with_state_builds() {
        use bitwarden_state::registry::StateRegistry;
        let registry = StateRegistry::new_with_memory_db();
        let _client = ClientBuilder::new().with_state(registry).build();
    }

    #[test]
    fn test_client_builder_with_state_in_chain() {
        use bitwarden_state::registry::StateRegistry;
        let registry = StateRegistry::new_with_memory_db();
        let _client = ClientBuilder::new()
            .with_settings(ClientSettings::default())
            .with_state(registry)
            .build();
    }
}
