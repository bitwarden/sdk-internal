use bitwarden_core::{Client, ClientSettings};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// The LoginClient is used to obtain identity / access tokens from the Bitwarden Identity API.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct LoginClient {
    pub(crate) client: Client,
}

impl LoginClient {
    /// Create a new LoginClient with the given core client settings
    pub(crate) fn new(settings: ClientSettings) -> Self {
        // build new client from client settings

        let core_client = Client::new(Some(settings.clone()));

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
