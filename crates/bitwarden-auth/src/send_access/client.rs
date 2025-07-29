use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[derive(Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct SendAccessClient {
    pub(crate) client: Client,
}

impl SendAccessClient {
    pub(crate) fn new(client: Client) -> Self {
        Self { client }
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl SendAccessClient {
    /// Request an access token for the provided send
    pub async fn request_send_access_token(&self, request: String) -> String {
        // TODO: This is just here to silence some warnings
        let _config = self.client.internal.get_api_configurations().await;
        request
    }
}
