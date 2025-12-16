use std::sync::Arc;

use bitwarden_core::{ClientName, ClientSettings};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

// TODO: consider initializing the Identity Client with the device and and client information directly and save on the client itself
// Doesn't make sense to pass core client to identity. Identity client should be more standalone and it should instantiate
// the core client in the future.

// TODO: rename this to LoginClient
// TODO: re-use ClientSettings from core crate

/// The LoginClient is used to obtain identity / access tokens from the Bitwarden Identity API.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct LoginClient {
    pub(crate) identity_api_client: bitwarden_api_identity::apis::ApiClient,
    // TODO: we have to save this since the ApiClient doesn't expose its configuration publicly
    pub(crate) identity_config: bitwarden_api_identity::apis::configuration::Configuration,
}

impl LoginClient {
    /// Create a new LoginClient with the given client settings
    pub(crate) fn new(settings: ClientSettings) -> Self {
        // Build headers for the HTTP client
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(
            "Device-Type",
            reqwest::header::HeaderValue::from_str(&(settings.device_type as u8).to_string())
                .expect("All numbers are valid ASCII"),
        );

        if let Some(client_type) = Into::<Option<ClientName>>::into(settings.device_type) {
            headers.append(
                "Bitwarden-Client-Name",
                reqwest::header::HeaderValue::from_str(&client_type.to_string())
                    .expect("All ASCII strings are valid header values"),
            );
        }

        if let Some(version) = &settings.bitwarden_client_version {
            headers.append(
                "Bitwarden-Client-Version",
                reqwest::header::HeaderValue::from_str(version)
                    .expect("Version should be a valid header value"),
            );
        }

        let http_client_builder = Self::new_http_client_builder().default_headers(headers);
        let http_client = http_client_builder
            .build()
            .expect("Failed to build HTTP client");

        // Create identity API configuration
        let identity_config = bitwarden_api_identity::apis::configuration::Configuration {
            base_path: settings.identity_url,
            user_agent: Some(settings.user_agent),
            client: http_client,
            basic_auth: None,
            oauth_access_token: None,
            bearer_access_token: None,
            api_key: None,
        };

        // Arc required for ApiClient's thread-safe configuration sharing
        let identity_config_arc: Arc<bitwarden_api_identity::apis::configuration::Configuration> =
            Arc::new(identity_config.clone());
        let identity_api_client =
            bitwarden_api_identity::apis::ApiClient::new(&identity_config_arc);

        Self {
            identity_api_client,
            identity_config,
        }
    }

    /// Create an HTTP client builder with proper TLS configuration
    fn new_http_client_builder() -> reqwest::ClientBuilder {
        #[allow(unused_mut)]
        let mut http_client_builder = reqwest::Client::builder();

        // TLS configuration for non-wasm targets
        #[cfg(not(target_arch = "wasm32"))]
        {
            use rustls::ClientConfig;
            use rustls_platform_verifier::ConfigVerifierExt;
            http_client_builder = http_client_builder.use_preconfigured_tls(
                ClientConfig::with_platform_verifier().expect("Failed to create platform verifier"),
            );

            // Enforce HTTPS for all requests in non-debug builds
            #[cfg(not(debug_assertions))]
            {
                http_client_builder = http_client_builder.https_only(true);
            }
        }

        http_client_builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_client_creation() {
        let client_settings: ClientSettings = ClientSettings::default();
        let login_client = LoginClient::new(client_settings.clone());

        // Verify identity_config fields
        assert_eq!(
            login_client.identity_config.base_path,
            "https://identity.bitwarden.com"
        );
        assert!(login_client.identity_config.user_agent.is_some());
        assert_eq!(
            login_client.identity_config.user_agent.unwrap(),
            client_settings.user_agent
        );

        // Verify optional auth fields are None (initially)
        assert!(login_client.identity_config.basic_auth.is_none());
        assert!(login_client.identity_config.oauth_access_token.is_none());
        assert!(login_client.identity_config.bearer_access_token.is_none());
        assert!(login_client.identity_config.api_key.is_none());

        // Verify the API client exists (type check)
        let _api_client = &login_client.identity_api_client;
        // The fact that this compiles and doesn't panic means it was created
    }

    #[test]
    fn test_login_client_with_custom_settings() {
        use bitwarden_core::DeviceType;

        let client_settings = ClientSettings {
            identity_url: "https://custom.identity.com".to_string(),
            api_url: "https://custom.api.com".to_string(),
            user_agent: "TestAgent/1.0.0".to_string(),
            device_type: DeviceType::SDK,
            bitwarden_client_version: Some("1.2.3".to_string()),
        };

        let login_client = LoginClient::new(client_settings.clone());

        assert_eq!(
            login_client.identity_config.base_path,
            "https://custom.identity.com"
        );
        assert_eq!(
            login_client.identity_config.user_agent,
            Some("TestAgent/1.0.0".to_string())
        );

        // Verify optional auth fields are None (initially)
        assert!(login_client.identity_config.basic_auth.is_none());
        assert!(login_client.identity_config.oauth_access_token.is_none());
        assert!(login_client.identity_config.bearer_access_token.is_none());
        assert!(login_client.identity_config.api_key.is_none());
    }
}
