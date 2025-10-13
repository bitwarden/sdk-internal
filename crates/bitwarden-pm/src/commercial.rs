use bitwarden_commercial_vault::CommercialVaultClientExt as _;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
/// Client for bitwarden licensed operations
pub struct CommercialPasswordManagerClient(bitwarden_core::Client);

impl CommercialPasswordManagerClient {
    pub(crate) fn new(client: bitwarden_core::Client) -> Self {
        Self(client)
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CommercialPasswordManagerClient {
    /// Vault item operations
    pub fn vault(&self) -> bitwarden_commercial_vault::CommercialVaultClient {
        self.0.vault()
    }
}
