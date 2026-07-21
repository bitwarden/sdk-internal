//! Feature flag retrieval, persistence, and refresh from the server `/config` endpoint.

use std::{collections::HashMap, sync::Arc};

use bitwarden_state::Setting;
use chrono::{DateTime, Duration, Utc};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Client,
    client::{
        flags::Flags,
        internal::ApiConfigurations,
        persisted_state::{FLAGS, FLAGS_FETCHED_AT},
    },
};

const FLAGS_TTL: Duration = Duration::hours(1);

/// Errors returned by [`FlagsClient::fetch`].
#[derive(Debug, thiserror::Error)]
pub enum FetchFlagsError {
    /// Network or deserialization error when fetching `/config`.
    #[error("failed to fetch /config: {0}")]
    Api(#[from] bitwarden_api_api::apis::Error),
    /// Error persisting flags or fetched_at timestamp to state registry.
    #[error("state access error: {0}")]
    State(#[from] bitwarden_state::SettingsError),
}

/// A client for inspecting and refreshing feature flags.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct FlagsClient {
    flags: Setting<Flags>,
    flags_fetched_at: Setting<DateTime<Utc>>,
    api_configurations: Arc<ApiConfigurations>,
}

impl FlagsClient {
    /// Persist a flag map (e.g. from `/config`) into the state registry.
    pub async fn load(&self, flags: HashMap<String, bool>) {
        let flags = Flags::load_from_map(flags);
        if let Err(e) = self.flags.update(flags).await {
            tracing::warn!("Failed to persist flags: {e}");
        }
    }

    /// Retrieve the active feature flags from the state registry.
    pub async fn get(&self) -> Flags {
        match self.flags.get().await {
            Ok(flags) => flags.unwrap_or_default(),
            Err(e) => {
                tracing::warn!("Failed to read flags, using defaults: {e}");
                Flags::default()
            }
        }
    }

    /// Fetch flags from `/config` and persist both the flag values and a `fetched_at` timestamp.
    ///
    /// Pass `force = true` from `from_authenticated_data` (PM-27624) immediately before
    /// `save_to_state`, so the initial flag fetch is part of the persisted login state.
    /// [`Client::load_from_state`] calls this with `force = false` to honour the 1-hour TTL.
    pub async fn fetch(&self, force: bool) -> Result<(), FetchFlagsError> {
        if !force {
            let last: Option<DateTime<Utc>> = self.flags_fetched_at.get().await?;
            if let Some(fetched_at) = last
                && Utc::now().signed_duration_since(fetched_at) < FLAGS_TTL
            {
                return Ok(());
            }
        }

        let config = self
            .api_configurations
            .api_client
            .config_api()
            .get_configs()
            .await?;
        let feature_states = config.feature_states.unwrap_or_default();
        // `/config` returns `serde_json::Value`; coerce to bool. Non-bool values are dropped
        // because `Flags` only models boolean flags today.
        let bool_map = feature_states
            .into_iter()
            .filter_map(|(k, v)| v.as_bool().map(|b| (k, b)))
            .collect();
        self.load(bool_map).await;
        self.flags_fetched_at.update(Utc::now()).await?;
        Ok(())
    }
}

impl Client {
    /// Access to feature flag retrieval, persistence, and refresh.
    pub fn flags(&self) -> FlagsClient {
        let registry = &self.internal.state_registry;
        FlagsClient {
            flags: registry
                .setting(FLAGS)
                .expect("Settings repository must be registered on the state registry"),
            flags_fetched_at: registry
                .setting(FLAGS_FETCHED_AT)
                .expect("Settings repository must be registered on the state registry"),
            api_configurations: self.internal.api_configurations.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;
    use crate::{ClientSettings, DeviceType};

    fn settings_for(server: &MockServer) -> ClientSettings {
        ClientSettings {
            identity_url: format!("http://{}", server.address()),
            api_url: format!("http://{}", server.address()),
            user_agent: "flags-tests".to_string(),
            device_type: DeviceType::SDK,
            device_identifier: None,
            bitwarden_client_version: None,
            bitwarden_package_type: None,
        }
    }

    async fn write_fetched_at(client: &Client, at: DateTime<Utc>) {
        client
            .internal
            .state_registry
            .setting(FLAGS_FETCHED_AT)
            .unwrap()
            .update(at)
            .await
            .unwrap();
    }

    async fn read_fetched_at(client: &Client) -> Option<DateTime<Utc>> {
        client
            .internal
            .state_registry
            .setting(FLAGS_FETCHED_AT)
            .unwrap()
            .get()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn load_round_trips_through_setting() {
        let client = Client::new(None);

        // With no flags loaded yet, get should return defaults.
        let initial = client.flags().get().await;
        assert!(!initial.strict_cipher_decryption);

        // Loading flags should persist them via the FLAGS setting.
        let mut map = HashMap::new();
        map.insert("pm-34500-strict-cipher-decryption".to_string(), true);
        client.flags().load(map).await;

        // get should now return the loaded values.
        let loaded = client.flags().get().await;
        assert!(loaded.strict_cipher_decryption);

        // The values should be readable directly from the setting too.
        let persisted = client
            .internal
            .state_registry
            .setting(FLAGS)
            .unwrap()
            .get()
            .await
            .unwrap()
            .expect("flags should be persisted after load");
        assert!(persisted.strict_cipher_decryption);
    }

    #[tokio::test]
    async fn fetch_force_persists_flags_and_timestamp() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "featureStates": { "pm-34500-strict-cipher-decryption": true }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new(Some(settings_for(&server)));
        let before = Utc::now();
        client.flags().fetch(true).await.unwrap();

        assert!(client.flags().get().await.strict_cipher_decryption);
        let fetched_at = read_fetched_at(&client)
            .await
            .expect("fetched_at must be set after a successful fetch");
        assert!(fetched_at >= before);
    }

    #[tokio::test]
    async fn fetch_skips_when_fresh() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(0)
            .mount(&server)
            .await;

        let client = Client::new(Some(settings_for(&server)));
        write_fetched_at(&client, Utc::now() - Duration::minutes(5)).await;

        client.flags().fetch(false).await.unwrap();
    }

    #[tokio::test]
    async fn fetch_force_ignores_ttl() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new(Some(settings_for(&server)));
        write_fetched_at(&client, Utc::now() - Duration::minutes(5)).await;

        client.flags().fetch(true).await.unwrap();
    }

    #[tokio::test]
    async fn fetch_refreshes_when_stale() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "featureStates": { "pm-34500-strict-cipher-decryption": true }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new(Some(settings_for(&server)));
        let stale = Utc::now() - Duration::hours(2);
        write_fetched_at(&client, stale).await;

        client.flags().fetch(false).await.unwrap();

        assert!(client.flags().get().await.strict_cipher_decryption);
        let fetched_at = read_fetched_at(&client).await.unwrap();
        assert!(fetched_at > stale);
    }

    #[tokio::test]
    async fn fetch_network_error_is_non_fatal_and_preserves_flags() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/config"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = Client::new(Some(settings_for(&server)));
        client
            .flags()
            .load(HashMap::from([(
                "pm-34500-strict-cipher-decryption".to_string(),
                true,
            )]))
            .await;

        assert!(client.flags().fetch(true).await.is_err());
        assert!(
            client.flags().get().await.strict_cipher_decryption,
            "previously persisted flags must survive a failed fetch"
        );
    }
}
