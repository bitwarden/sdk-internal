//! End-to-end test for [`FromClientShared`] and the blanket `FromClientPart<Arc<T>>` impl.
//!
//! Demonstrates the pattern feature clients follow when they want to expose a mockable trait
//! that other clients can hold as `Arc<dyn FooTrait>` through `#[derive(FromClient)]`.

use std::sync::Arc;

use bitwarden_core::{Client, FromClient, client::ApiConfigurations};
use bitwarden_core_macro::client_trait;

/// Stand-in feature client used to exercise the `FromClientShared` bridge end-to-end.
struct InnerClient {
    api_configurations: Arc<ApiConfigurations>,
}

trait InnerClientExt {
    fn inner(&self) -> InnerClient;
}

impl InnerClientExt for Client {
    fn inner(&self) -> InnerClient {
        InnerClient {
            api_configurations: self.internal.get_api_configurations(),
        }
    }
}

/// Public surface of `InnerClient` that dependent clients hold as `Arc<dyn InnerClientTrait>`.
/// `#[client_trait]` emits the matching `FromClientShared` bridge; `#[mockall::automock]`
/// provides `MockInnerClientTrait` for tests.
#[client_trait(via = client.inner())]
#[cfg_attr(any(test, feature = "test-fixtures"), mockall::automock)]
#[async_trait::async_trait]
#[allow(missing_docs)]
trait InnerClientTrait: Send + Sync {
    fn server_url(&self) -> String;
    async fn fetch(&self, key: String) -> String;
}

#[async_trait::async_trait]
impl InnerClientTrait for InnerClient {
    fn server_url(&self) -> String {
        self.api_configurations.api_config.base_path.clone()
    }

    #[allow(clippy::unused_async)]
    async fn fetch(&self, key: String) -> String {
        format!("{}={}", key, self.server_url())
    }
}

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

#[test]
fn outer_constructed_via_from_client() {
    let client = Client::new(None);
    let outer = OuterClient::from_client(&client);
    assert!(outer.announce().starts_with("[outer] "));
}

#[test]
fn outer_swaps_in_mock_inner() {
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
async fn outer_swaps_in_mock_inner_for_async() {
    let mut mock = MockInnerClientTrait::new();
    mock.expect_fetch()
        .times(1)
        .returning(|key| format!("mocked:{}", key));

    let outer = OuterClient {
        inner: Arc::new(mock),
    };
    assert_eq!(outer.lookup("k1").await, "found: mocked:k1");
}
