use std::sync::Arc;

use bitwarden_core::platform::FingerprintRequest;
use bitwarden_vault::Cipher;

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

    pub fn store(self: Arc<Self>) -> StoreClient {
        StoreClient(self.0.clone())
    }
}

#[derive(uniffi::Object)]
pub struct StoreClient(pub(crate) Arc<Client>);

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait CipherStore: Send + Sync {
    async fn get(&self, id: String) -> Option<Cipher>;
    async fn list(&self) -> Vec<Cipher>;
    async fn set(&self, id: String, value: Cipher);
    async fn remove(&self, id: String);
}

impl<T> std::fmt::Debug for UniffiTraitBridge<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UniffiTraitBridge").finish()
    }
}

struct UniffiTraitBridge<T>(T);

#[async_trait::async_trait]
impl bitwarden_core::client::data_store::DataStore<Cipher>
    for UniffiTraitBridge<Arc<dyn CipherStore>>
{
    async fn get(&self, key: String) -> Option<Cipher> {
        self.0.get(key).await
    }
    async fn list(&self) -> Vec<Cipher> {
        self.0.list().await
    }
    async fn set(&self, key: String, value: Cipher) {
        self.0.set(key, value).await
    }
    async fn remove(&self, key: String) {
        self.0.remove(key).await
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl StoreClient {
    pub async fn print_the_ciphers(&self) -> String {
        let store = self.0 .0.internal.get_data_store::<Cipher>().expect("msg");
        let mut result = String::new();
        let ciphers = store.list().await;
        for cipher in ciphers {
            result.push_str(&serde_json::to_string(&cipher).expect("msg"));
            result.push('\n');
        }
        result
    }

    pub fn register_cipher_store(&self, store: Arc<dyn CipherStore>) -> Result<()> {
        let store_internal = Arc::new(UniffiTraitBridge(store));
        self.0 .0.internal.register_data_store(store_internal);
        Ok(())
    }
}
