use std::sync::Arc;

use bitwarden_core::{platform::FingerprintRequest, Client};
use bitwarden_fido::ClientFido2Ext;
use bitwarden_vault::Cipher;
use repository::UniffiRepositoryBridge;

use crate::error::{Error, Result};

mod fido2;
mod repository;

#[derive(uniffi::Object)]
pub struct PlatformClient(pub(crate) bitwarden_core::Client);

#[uniffi::export]
impl PlatformClient {
    /// Fingerprint (public key)
    pub fn fingerprint(&self, req: FingerprintRequest) -> Result<String> {
        Ok(self
            .0
            .platform()
            .fingerprint(&req)
            .map_err(Error::Fingerprint)?)
    }

    /// Fingerprint using logged in user's public key
    pub fn user_fingerprint(&self, fingerprint_material: String) -> Result<String> {
        Ok(self
            .0
            .platform()
            .user_fingerprint(fingerprint_material)
            .map_err(Error::UserFingerprint)?)
    }

    /// Load feature flags into the client
    pub fn load_flags(&self, flags: std::collections::HashMap<String, bool>) -> Result<()> {
        self.0.internal.load_flags(flags);
        Ok(())
    }

    /// FIDO2 operations
    pub fn fido2(&self) -> fido2::ClientFido2 {
        fido2::ClientFido2(self.0.fido2())
    }

    pub fn state(&self) -> StateClient {
        StateClient(self.0.clone())
    }
}

#[derive(uniffi::Object)]
pub struct StateClient(Client);

repository::create_uniffi_repository!(CipherRepository, Cipher);

#[uniffi::export]
impl StateClient {
    pub fn register_cipher_repository(&self, store: Arc<dyn CipherRepository>) {
        let store_internal = UniffiRepositoryBridge::new(store);
        self.0
            .platform()
            .state()
            .register_client_managed(store_internal)
    }
}
