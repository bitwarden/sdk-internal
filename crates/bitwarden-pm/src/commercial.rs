use bitwarden_commercial_vault::CommercialVaultClientExt as _;
use bitwarden_pam::PamClientExt as _;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[bitwarden_ffi::wasm_object]
/// Client for bitwarden licensed operations
pub struct CommercialPasswordManagerClient(bitwarden_core::Client);

impl CommercialPasswordManagerClient {
    pub(crate) fn new(client: bitwarden_core::Client) -> Self {
        Self(client)
    }
}

#[bitwarden_ffi::wasm_export]
impl CommercialPasswordManagerClient {
    /// Vault item operations
    pub fn vault(&self) -> bitwarden_commercial_vault::CommercialVaultClient {
        self.0.vault()
    }

    /// Privileged Access Management (PAM) operations
    pub fn pam(&self) -> bitwarden_pam::PamClient {
        self.0.pam()
    }
}
