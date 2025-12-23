use bitwarden_core::{Client, ClientSettings};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Client for authenticating Bitwarden users.
///
/// The `LoginClient` handles unauthenticated operations to obtain access tokens
/// from the Bitwarden Identity API.
///
/// # Purpose
///
/// Use `LoginClient` to:
/// - Authenticate users via various login mechanisms (password, SSO, etc.)

///
/// # Lifecycle
///
/// 1. **Create**: Instantiate a `LoginClient` with [`LoginClient::new`] using unauthenticated
///    [`ClientSettings`]
/// 2. **Authenticate**: Call login methods (e.g., [`login_via_password`])
/// 3. **Use Tokens**: Pass the returned tokens to create an authenticated core client
///
/// # Available Login Methods
///
/// - **Password-based**: [`login_via_password`] - Authenticate with email and master password (2FA
///   not yet supported)
///
/// - **Future**: SSO, device-based authentication, etc.
///
/// # Relationship to Other Clients
///
/// - `LoginClient` is for **unauthenticated** operations (logging in)
/// - The core client is for **authenticated** operations (managing vault, etc.)
/// - After successful login, discard the `LoginClient` and create a core client
///
/// # Example
///
/// ```rust,no_run
/// # use bitwarden_auth::identity::LoginClient;
/// # use bitwarden_core::{ClientSettings, DeviceType};
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create an unauthenticated login client
/// let settings = ClientSettings {
///     identity_url: "https://identity.bitwarden.com".to_string(),
///     api_url: "https://api.bitwarden.com".to_string(),
///     user_agent: "MyApp/1.0".to_string(),
///     device_type: DeviceType::SDK,
///     device_identifier: None,
///     bitwarden_client_version: None,
///     bitwarden_package_type: None,
/// };
/// let login_client = LoginClient::new(settings);
///
/// // Use login_client to authenticate...
/// // (See login_via_password module for complete example)
/// # Ok(())
/// # }
/// ```
///
/// [`login_via_password`]: LoginClient::login_via_password
/// [`bitwarden_pm::PasswordManagerClient`]: https://docs.rs/bitwarden-pm/latest/bitwarden_pm/struct.PasswordManagerClient.html
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
