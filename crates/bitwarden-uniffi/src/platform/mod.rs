use std::sync::Arc;

use bitwarden_core::platform::FingerprintRequest;

use crate::{
    error::{Error, Result},
    Client,
};

mod fido2;

#[derive(uniffi::Object)]
pub struct PlatformClient(pub(crate) Arc<Client>);

#[uniffi::export]
impl PlatformClient {
    /// Fingerprint (public key)
    pub fn fingerprint(&self, req: FingerprintRequest) -> Result<String> {
        Ok(self
            .0
             .0
            .platform()
            .fingerprint(&req)
            .map_err(Error::Fingerprint)?)
    }

    /// Fingerprint using logged in user's public key
    pub fn user_fingerprint(&self, fingerprint_material: String) -> Result<String> {
        Ok(self
            .0
             .0
            .platform()
            .user_fingerprint(fingerprint_material)
            .map_err(Error::UserFingerprint)?)
    }

    /// Load feature flags into the client
    pub fn load_flags(&self, flags: std::collections::HashMap<String, bool>) -> Result<()> {
        self.0 .0.internal.load_flags(flags);
        Ok(())
    }

    /// FIDO2 operations
    pub fn fido2(self: Arc<Self>) -> Arc<fido2::ClientFido2> {
        Arc::new(fido2::ClientFido2(self.0.clone()))
    }
}
