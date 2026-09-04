//! End-to-end test for reading and writing a [`Value`] through a [`Client`], both from the
//! `state().value::<K>()` accessor and from a field wired up by `#[derive(FromClient)]`.

use bitwarden_core::{Client, client::FromClient};
use bitwarden_core_macro::FromClient;
use bitwarden_state::{Value, register_value_key};

register_value_key!(THEME: String = "value_injection_test_theme");

#[derive(FromClient)]
struct TestClient {
    theme: Value<THEME>,
}

#[tokio::test]
async fn test_value_roundtrip_through_client() {
    let client = Client::new(None);

    client
        .platform()
        .state()
        .value::<THEME>()
        .set("dark".to_string())
        .await
        .unwrap();

    // The injected handle reads the same storage as the accessor.
    let injected = TestClient::from_client(&client);
    assert_eq!(injected.theme.get().await.unwrap(), "dark");
}
