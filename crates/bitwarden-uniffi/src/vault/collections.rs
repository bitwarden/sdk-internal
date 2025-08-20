use std::sync::Arc;

use crate::{error::Error, Result};
use bitwarden_collections::collection::{Collection, CollectionView};
use bitwarden_vault::collection_client::CollectionViewTree;

#[allow(missing_docs)]
#[derive(uniffi::Object)]
pub struct CollectionsClient(pub(crate) bitwarden_vault::collection_client::CollectionsClient);

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

    ///
    /// Returns the vector of CollectionView objects in a tree structure based on its implemented
    /// path().
    pub fn get_collection_tree(&self, collections: Vec<CollectionView>) -> Arc<CollectionViewTree> {
        Arc::new(self.0.get_collection_tree(collections))
    }
}