use bitwarden_vault::{Collection, CollectionView};

use crate::{error::Error, Result};

#[derive(uniffi::Object)]
pub struct CollectionsClient(pub(crate) bitwarden_vault::CollectionsClient);

#[uniffi::export]
impl CollectionsClient {
    /// Decrypt collection
    pub fn decrypt(&self, collection: Collection) -> Result<CollectionView> {
        Ok(self.0.decrypt(collection).map_err(Error::Decrypt)?)
    }

    /// Decrypt collection list
    pub fn decrypt_list(&self, collections: Vec<Collection>) -> Result<Vec<CollectionView>> {
        Ok(self.0.decrypt_list(collections).map_err(Error::Decrypt)?)
    }
}
