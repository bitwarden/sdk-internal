use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// The IdentityClient is used to obtain identity / access tokens from the Bitwarden Identity API.
#[derive(Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct IdentityClient {
    pub(crate) client: Client,
}

impl IdentityClient {
    /// Create a new IdentityClient with the given Client.
    pub(crate) fn new(client: Client) -> Self {
        Self { client }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_client_creation() {
        let client: Client = Client::new(None);
        let identity_client = IdentityClient::new(client);

        // Verify the identity client was created successfully
        // The client field is present and accessible
        let _ = identity_client.client;
    }
}
