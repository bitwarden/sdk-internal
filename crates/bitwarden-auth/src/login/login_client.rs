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
/// 1. Create `LoginClient` via `AuthClient`
/// 2. Call login method
/// 3. Use returned tokens with authenticated core client
///
/// # Password Login Example
///
/// ```rust,no_run
/// # use bitwarden_auth::{AuthClient, login::login_via_password::PasswordLoginRequest};
/// # use bitwarden_auth::login::models::{LoginRequest, LoginDeviceRequest, LoginResponse};
/// # use bitwarden_core::{Client, ClientSettings, DeviceType};
/// # async fn example(email: String, password: String) -> Result<(), Box<dyn std::error::Error>> {
/// // Create auth client
/// let client = Client::new(None);
/// let auth_client = AuthClient::new(client);
///
/// // Configure client settings and create login client
/// let settings = ClientSettings {
///     identity_url: "https://identity.bitwarden.com".to_string(),
///     api_url: "https://api.bitwarden.com".to_string(),
///     user_agent: "MyApp/1.0".to_string(),
///     device_type: DeviceType::SDK,
///     device_identifier: None,
///     bitwarden_client_version: None,
///     bitwarden_package_type: None,
/// };
/// let login_client = auth_client.login(settings);
///
/// // Get user's KDF config
/// let prelogin = login_client.get_password_prelogin(email.clone()).await?;
///
/// // Login with credentials
/// let response = login_client.login_via_password(PasswordLoginRequest {
///     login_request: LoginRequest {
///         client_id: "connector".to_string(),
///         device: LoginDeviceRequest {
///             device_type: DeviceType::SDK,
///             device_identifier: "device-id".to_string(),
///             device_name: "My Device".to_string(),
///             device_push_token: None,
///         },
///     },
///     email,
///     password,
///     prelogin_response: prelogin,
/// }).await?;
///
/// // Use tokens from response for authenticated requests
/// match response {
///     LoginResponse::Authenticated(success) => {
///         let access_token = success.access_token;
///         // Use access_token for authenticated requests
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct LoginClient {
    pub(crate) client: Client,
}

impl LoginClient {
    /// Creates a new `LoginClient` with the given client settings.
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
