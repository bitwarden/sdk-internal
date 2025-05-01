use bitwarden_vault::{Cipher, CipherListView, CipherView, Fido2CredentialView};
use uuid::Uuid;

use crate::{error::Error, Result};

#[derive(uniffi::Object)]
pub struct CiphersClient(pub(crate) bitwarden_vault::CiphersClient);

#[uniffi::export]
impl CiphersClient {
    /// Encrypt cipher
    pub fn encrypt(&self, cipher_view: CipherView) -> Result<Cipher> {
        Ok(self.0.encrypt(cipher_view).map_err(Error::Encrypt)?)
    }

    /// Decrypt cipher
    pub fn decrypt(&self, cipher: Cipher) -> Result<CipherView> {
        Ok(self.0.decrypt(cipher).map_err(Error::Decrypt)?)
    }

    /// Decrypt cipher list
    pub fn decrypt_list(&self, ciphers: Vec<Cipher>) -> Result<Vec<CipherListView>> {
        Ok(self.0.decrypt_list(ciphers).map_err(Error::Decrypt)?)
    }

    pub fn decrypt_fido2_credentials(
        &self,
        cipher_view: CipherView,
    ) -> Result<Vec<Fido2CredentialView>> {
        Ok(self
            .0
            .decrypt_fido2_credentials(cipher_view)
            .map_err(Error::Decrypt)?)
    }

    /// Move a cipher to an organization, reencrypting the cipher key if necessary
    pub fn move_to_organization(
        &self,
        cipher: CipherView,
        organization_id: Uuid,
    ) -> Result<CipherView> {
        Ok(self
            .0
            .move_to_organization(cipher, organization_id)
            .map_err(Error::Cipher)?)
    }
}
