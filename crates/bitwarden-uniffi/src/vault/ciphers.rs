use std::sync::Arc;

use bitwarden::vault::{Cipher, CipherListView, CipherView};
use uuid::Uuid;

use crate::{Client, Result};

#[derive(uniffi::Object)]
pub struct ClientCiphers(pub Arc<Client>);

#[uniffi::export(async_runtime = "tokio")]
impl ClientCiphers {
    /// Encrypt cipher
    pub async fn encrypt(&self, cipher_view: CipherView) -> Result<Cipher> {
        Ok(self
            .0
             .0
            .write()
            .await
            .vault()
            .ciphers()
            .encrypt(cipher_view)?)
    }

    /// Decrypt cipher
    pub async fn decrypt(&self, cipher: Cipher) -> Result<CipherView> {
        Ok(self.0 .0.write().await.vault().ciphers().decrypt(cipher)?)
    }

    /// Decrypt cipher list
    pub async fn decrypt_list(&self, ciphers: Vec<Cipher>) -> Result<Vec<CipherListView>> {
        Ok(self
            .0
             .0
            .write()
            .await
            .vault()
            .ciphers()
            .decrypt_list(ciphers)?)
    }

    /// Move a cipher to an organization, reencrypting the cipher key if necessary
    pub async fn move_to_organization(
        &self,
        cipher: CipherView,
        organization_id: Uuid,
    ) -> Result<CipherView> {
        Ok(self
            .0
             .0
            .write()
            .await
            .vault()
            .ciphers()
            .move_to_organization(cipher, organization_id)?)
    }
}
