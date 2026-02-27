use std::sync::{Arc, OnceLock, RwLock};

use bitwarden_crypto::KeyStore;
#[cfg(feature = "internal")]
use bitwarden_state::registry::StateRegistry;
use reqwest::header::{self, HeaderValue};

use super::internal::InternalClient;
#[cfg(feature = "internal")]
use crate::client::flags::Flags;
use crate::{
    auth::auth_tokens::{NoopTokenHandler, TokenHandler},
    client::{
        client_settings::{ClientName, ClientSettings},
        internal::ApiConfigurations,
    },
};

/// The main struct to interact with the Bitwarden SDK.
#[derive(Clone)]
pub struct Client {
    // Important: The [`Client`] struct requires its `Clone` implementation to return an owned
    // reference to the same instance. This is required to properly use the FFI API, where we can't
    // just use normal Rust references effectively. For this to happen, any mutable state needs
    // to be behind an Arc, ideally as part of the existing [`InternalClient`] struct.
    #[doc(hidden)]
    pub internal: Arc<InternalClient>,
}

impl Client {
    /// Create a new Bitwarden client with default settings and a no-op token handler.
    pub fn new(settings: Option<ClientSettings>) -> Self {
        Self::new_internal(settings, Arc::new(NoopTokenHandler), None)
    }

    /// Create a new Bitwarden client with the specified token handler for managing authentication
    /// tokens.
    pub fn new_with_token_handler(
        settings: Option<ClientSettings>,
        token_handler: Arc<dyn TokenHandler>,
    ) -> Self {
        Self::new_internal(settings, token_handler, None)
    }

    fn new_internal(
        settings_input: Option<ClientSettings>,
        token_handler: Arc<dyn TokenHandler>,
        cookie_middleware: Option<Arc<dyn reqwest_middleware::Middleware>>,
    ) -> Self {
        let settings = settings_input.unwrap_or_default();

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
            user_agent: Some(settings.user_agent.clone()),
            client: bw_http_client.clone().into(),
            oauth_access_token: None,
        };

        // Create the client for the API service, with authentication middleware.
        let auth_middleware = token_handler.initialize_middleware(
            login_method.clone(),
            identity.clone(),
            key_store.clone(),
        );

        // Register cookie middleware BEFORE auth middleware per ADR-056
        let mut client_builder = reqwest_middleware::ClientBuilder::new(bw_http_client);
        if let Some(cookie_mw) = cookie_middleware {
            client_builder = client_builder.with_arc(cookie_mw);
        }
        let bw_http_client = client_builder.with_arc(auth_middleware).build();
        let api = bitwarden_api_api::Configuration {
            base_path: settings.api_url,
            user_agent: Some(settings.user_agent),
            client: bw_http_client,
            oauth_access_token: None,
        };

        Self {
            internal: Arc::new(InternalClient {
                user_id: OnceLock::new(),
                token_handler,
                login_method,
                #[cfg(feature = "internal")]
                flags: RwLock::new(Flags::default()),
                api_configurations: ApiConfigurations::new(identity, api, settings.device_type),
                external_http_client,
                key_store,
                #[cfg(feature = "internal")]
                security_state: RwLock::new(None),
                #[cfg(feature = "internal")]
                repository_map: StateRegistry::new(),
            }),
        }
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

    // TODO: PM-29938 - Since we now add this header always, we need to remove this from the
    // auto-generated code
    headers.append(
        reqwest::header::USER_AGENT,
        HeaderValue::from_str(&settings.user_agent)
            .expect("User agent should be a valid header value"),
    );

    headers
}
