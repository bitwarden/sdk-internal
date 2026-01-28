use std::sync::{Arc, OnceLock, RwLock};

use bitwarden_crypto::KeyStore;
#[cfg(feature = "internal")]
use bitwarden_state::registry::StateRegistry;
use reqwest::header::{self, HeaderValue};

use super::internal::InternalClient;
#[cfg(feature = "internal")]
use crate::client::flags::Flags;
use crate::client::{
    client_settings::{ClientName, ClientSettings},
    internal::{ApiConfigurations, ClientManagedTokens, SdkManagedTokens, Tokens},
};

/// The main struct to interact with the Bitwarden SDK.
#[derive(Debug, Clone)]
pub struct Client {
    // Important: The [`Client`] struct requires its `Clone` implementation to return an owned
    // reference to the same instance. This is required to properly use the FFI API, where we can't
    // just use normal Rust references effectively. For this to happen, any mutable state needs
    // to be behind an Arc, ideally as part of the existing [`InternalClient`] struct.
    #[doc(hidden)]
    pub internal: Arc<InternalClient>,
}

impl Client {
    /// Create a new Bitwarden client with SDK-managed tokens.
    pub fn new(settings: Option<ClientSettings>) -> Self {
        Self::new_internal(settings, Tokens::SdkManaged(SdkManagedTokens::default()))
    }

    /// Create a new Bitwarden client with client-managed tokens.
    pub fn new_with_client_tokens(
        settings: Option<ClientSettings>,
        tokens: Arc<dyn ClientManagedTokens>,
    ) -> Self {
        Self::new_internal(settings, Tokens::ClientManaged(tokens))
    }

    fn new_internal(settings_input: Option<ClientSettings>, tokens: Tokens) -> Self {
        let settings = settings_input.unwrap_or_default();

        let external_http_client = new_http_client_builder()
            .build()
            .expect("External HTTP Client build should not fail");

        let headers = build_default_headers(&settings);

        let bw_http_client = new_http_client_builder()
            .default_headers(headers)
            .build()
            .expect("Bw HTTP Client build should not fail");

        let bw_http_client = reqwest_middleware::ClientBuilder::new(bw_http_client).build();

        let identity = bitwarden_api_identity::apis::configuration::Configuration {
            base_path: settings.identity_url,
            user_agent: Some(settings.user_agent.clone()),
            client: bw_http_client.clone(),
            basic_auth: None,
            oauth_access_token: None,
            bearer_access_token: None,
            api_key: None,
        };

        let api = bitwarden_api_api::apis::configuration::Configuration {
            base_path: settings.api_url,
            user_agent: Some(settings.user_agent),
            client: bw_http_client,
            basic_auth: None,
            oauth_access_token: None,
            bearer_access_token: None,
            api_key: None,
        };

        Self {
            internal: Arc::new(InternalClient {
                user_id: OnceLock::new(),
                tokens: RwLock::new(tokens),
                login_method: RwLock::new(None),
                #[cfg(feature = "internal")]
                flags: RwLock::new(Flags::default()),
                __api_configurations: RwLock::new(ApiConfigurations::new(
                    identity,
                    api,
                    settings.device_type,
                )),
                external_http_client,
                key_store: KeyStore::default(),
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
