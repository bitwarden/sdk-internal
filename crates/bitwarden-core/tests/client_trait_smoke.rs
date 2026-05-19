//! Smoke tests for the `#[client_trait]` attribute macro.
//!
//! Two scenarios:
//!
//! 1. **Test-side mocking** - construct an `OuterClient` by hand, passing a
//!    `MockInnerClientTrait` so the test verifies how `OuterClient` interacts with its
//!    dependency.
//! 2. **Production wiring through `FromClient`** - `InnerClient` derives `FromClient` and
//!    has `#[client_trait]` applied to its inherent impl. The macro emits both
//!    `InnerClientTrait` *and* a `FromClientDyn` impl on `dyn InnerClientTrait`, which
//!    bridges through the blanket `FromClientPart<Arc<T>> for Client` so `OuterClient`'s
//!    `#[derive(FromClient)]` can pull an `Arc<dyn InnerClientTrait>` field straight out
//!    of a `Client` with no hand-written bridge.

use std::sync::Arc;

use bitwarden_core::{Client, FromClient, client::ApiConfigurations};
use bitwarden_core_macro::client_trait;

// --- Inner client: the dependency. Pulls its own state from `Client`. ---

#[derive(FromClient)]
struct InnerClient {
    api_configurations: Arc<ApiConfigurations>,
}

#[client_trait]
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

// --- Outer client: derives `FromClient` and consumes the inner via the trait. ---

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

// --- Tests ---

#[test]
fn outer_can_be_constructed_via_from_client() {
    let client = Client::new(None);
    let outer = OuterClient::from_client(&client);

    // The real `InnerClient` is wired in - `server_url` comes from the default API
    // configuration baked into a freshly-constructed `Client`.
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
    let inner = InnerClient::from_client(&client);
    assert_eq!(inner.private_helper(), "private");
    assert_eq!(inner.skipped(), "skipped");
}
