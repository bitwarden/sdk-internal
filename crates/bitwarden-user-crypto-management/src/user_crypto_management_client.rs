//! Client to manage the cryptographic machinery of a user account, including key-rotation

use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Client for managing the cryptographic machinery of a user account, including key-rotation.
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct UserCryptoManagementClient {
    #[allow(unused)]
    pub(crate) client: Client,
}

impl UserCryptoManagementClient {
    #[allow(unused)]
    pub(crate) fn new(client: Client) -> Self {
        Self { client }
    }
}

/// Extension trait to add the user-crypto-management client to the main Bitwarden SDK client.
pub trait UserCryptoManagementClientExt {
    /// Get the user-crypto-management client.
    fn user_crypto_management(&self) -> UserCryptoManagementClient;
}

impl UserCryptoManagementClientExt for Client {
    fn user_crypto_management(&self) -> UserCryptoManagementClient {
        UserCryptoManagementClient::new(self.clone())
    }
}
