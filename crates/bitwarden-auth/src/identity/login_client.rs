use bitwarden_core::{Client, ClientSettings};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Client for authenticating Bitwarden users.
///
/// Handles unauthenticated operations to obtain access tokens from the Identity API.
/// After successful authentication, use the returned tokens to create an authenticated core client.
///
/// # Lifecycle
///
/// 1. Create `LoginClient` via `AuthClient` → 2. Call login method → 3. Use returned tokens with
///    authenticated core client
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct LoginClient {
    pub(crate) client: Client,
}

impl LoginClient {
    /// Creates a new `LoginClient` with the given client settings.
    ///
    /// # Arguments
    ///
    /// * `settings` - Configuration for API endpoints, user agent, and device information
    ///
    /// # Note
    ///
    /// This method is `pub(crate)` because `LoginClient` instances should be obtained through
    /// the AuthClient. Direct instantiation is internal to the crate.
    pub(crate) fn new(settings: ClientSettings) -> Self {
        let core_client = Client::new(Some(settings));

        Self {
            client: core_client,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_client_creation() {
        let client_settings = ClientSettings::default();
        let login_client = LoginClient::new(client_settings);

        // Verify the internal client exists (type check)
        let _client = &login_client.client;
        // The fact that this compiles and doesn't panic means the client was created successfully
    }
}
