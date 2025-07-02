use std::sync::{Arc, OnceLock, RwLock};

use bitwarden_crypto::KeyStore;
#[cfg(feature = "internal")]
use bitwarden_state::registry::StateRegistry;
use reqwest::header::{self, HeaderValue};

use super::internal::InternalClient;
#[cfg(feature = "internal")]
use crate::client::flags::Flags;
use crate::client::{
    client_settings::ClientSettings,
    internal::{ApiConfigurations, Tokens},
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
    #[allow(missing_docs)]
    pub fn new(settings_input: Option<ClientSettings>) -> Self {
        let settings = settings_input.unwrap_or_default();

        fn new_client_builder() -> reqwest::ClientBuilder {
            #[allow(unused_mut)]
            let mut client_builder = reqwest::Client::builder();

            #[cfg(not(target_arch = "wasm32"))]
            {
                use rustls::ClientConfig;
                use rustls_platform_verifier::ConfigVerifierExt;
                client_builder = client_builder.use_preconfigured_tls(
                    ClientConfig::with_platform_verifier()
                        .expect("Failed to create platform verifier"),
                );
            }

            client_builder
        }

        let external_client = new_client_builder().build().expect("Build should not fail");

        let mut headers = header::HeaderMap::new();
        headers.append(
            "Device-Type",
            HeaderValue::from_str(&(settings.device_type as u8).to_string())
                .expect("All numbers are valid ASCII"),
        );
        let client_builder = new_client_builder().default_headers(headers);

        let client = client_builder.build().expect("Build should not fail");

        let identity = bitwarden_api_identity::apis::configuration::Configuration {
            base_path: settings.identity_url,
            user_agent: Some(settings.user_agent.clone()),
            client: client.clone(),
            basic_auth: None,
            oauth_access_token: None,
            bearer_access_token: None,
            api_key: None,
        };

        let api = bitwarden_api_api::apis::configuration::Configuration {
            base_path: settings.api_url,
            user_agent: Some(settings.user_agent),
            client,
            basic_auth: None,
            oauth_access_token: None,
            bearer_access_token: None,
            api_key: None,
        };

        Self {
            internal: Arc::new(InternalClient {
                user_id: OnceLock::new(),
                tokens: RwLock::new(Tokens::default()),
                login_method: RwLock::new(None),
                #[cfg(feature = "internal")]
                flags: RwLock::new(Flags::default()),
                __api_configurations: RwLock::new(Arc::new(ApiConfigurations {
                    identity,
                    api,
                    device_type: settings.device_type,
                })),
                external_client,
                key_store: KeyStore::default(),
                #[cfg(feature = "internal")]
                repository_map: StateRegistry::new(),
            }),
        }
    }
}
