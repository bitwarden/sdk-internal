//! Smoke tests for the `#[client_trait]` attribute macro.
//!
//! Mirrors how feature clients are wired in the rest of the SDK: each one is reachable from a
//! `Client` through an extension trait (`SyncClientExt::sync`, `VaultClientExt::vault`, etc.).
//! `#[client_trait(via = client.inner())]` reuses that extension method as the constructor for
//! the auto-bridge - no `FromClient` derive on the inner client required.

use std::sync::Arc;

use bitwarden_core::{Client, FromClient, client::ApiConfigurations};
use bitwarden_core_macro::client_trait;

/// Inner client - Represents a dependency of another feature client
struct InnerClient {
    api_configurations: Arc<ApiConfigurations>,
}

impl InnerClient {
    fn new(client: &Client) -> Self {
        Self {
            api_configurations: client.internal.get_api_configurations(),
        }
    }
}

trait InnerClientExt {
    fn inner(&self) -> InnerClient;
}

impl InnerClientExt for Client {
    fn inner(&self) -> InnerClient {
        InnerClient::new(self)
    }
}

#[client_trait(via = client.inner())]
impl InnerClient {
    pub fn server_url(&self) -> String {
        self.api_configurations.api_config.base_path.clone()
    }

    #[allow(clippy::unused_async)]
    pub async fn fetch(&self, key: String) -> String {
        format!("{}={}", key, self.server_url())
    }

    // Private helpers stay off the generated trait.
    #[allow(dead_code)]
    fn private_helper(&self) -> &'static str {
        "private"
    }

    // Public-but-opted-out methods stay off the generated trait.
    #[allow(dead_code)]
    #[client_trait(skip)]
    pub fn skipped(&self) -> &'static str {
        "skipped"
    }
}

/// Outer client which consumes `InnerClient` as a dependency
#[derive(FromClient)]
struct OuterClient {
    inner: Arc<dyn InnerClientTrait>,
}

impl OuterClient {
    fn announce(&self) -> String {
        format!("[outer] {}", self.inner.server_url())
    }

    async fn lookup(&self, key: &str) -> String {
        format!("found: {}", self.inner.fetch(key.to_string()).await)
    }
}

/// A client trait without `via` - no auto-bridge, but the trait + mock still exist.
struct StandaloneClient;

#[client_trait]
impl StandaloneClient {
    pub fn ping(&self) -> &'static str {
        "pong"
    }
}

#[test]
fn outer_can_be_constructed_via_from_client() {
    let client = Client::new(None);
    let outer = OuterClient::from_client(&client);

    // The real `InnerClient` is wired in through `InnerClientExt::inner` - `server_url`
    // comes from the default API configuration baked into a freshly-constructed `Client`.
    let announced = outer.announce();
    assert!(announced.starts_with("[outer] "));
}

#[test]
fn outer_can_be_tested_with_mock_inner() {
    let mut mock = MockInnerClientTrait::new();
    mock.expect_server_url()
        .times(1)
        .returning(|| "https://mocked.example.com".to_string());

    let outer = OuterClient {
        inner: Arc::new(mock),
    };
    assert_eq!(outer.announce(), "[outer] https://mocked.example.com");
}

#[tokio::test]
async fn outer_async_method_uses_mock_inner() {
    let mut mock = MockInnerClientTrait::new();
    mock.expect_fetch()
        .times(1)
        .returning(|key| format!("mocked:{}", key));

    let outer = OuterClient {
        inner: Arc::new(mock),
    };
    assert_eq!(outer.lookup("k1").await, "found: mocked:k1");
}

#[test]
fn private_and_skipped_methods_stay_on_inherent_impl() {
    let client = Client::new(None);
    let inner = client.inner();
    assert_eq!(inner.private_helper(), "private");
    assert_eq!(inner.skipped(), "skipped");
}

#[test]
fn standalone_client_without_via_still_has_trait_and_mock() {
    // No `via` means no `FromClientDyn` impl, but the trait + mock still exist.
    let concrete: Box<dyn StandaloneClientTrait> = Box::new(StandaloneClient);
    assert_eq!(concrete.ping(), "pong");

    let mut mock = MockStandaloneClientTrait::new();
    mock.expect_ping().returning(|| "mocked-pong");
    let via_mock: Box<dyn StandaloneClientTrait> = Box::new(mock);
    assert_eq!(via_mock.ping(), "mocked-pong");
}
