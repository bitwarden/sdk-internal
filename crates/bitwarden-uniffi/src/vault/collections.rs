use std::{collections::HashMap, sync::Arc};

use bitwarden_collections::{
    collection::{Collection, CollectionView},
    tree::{NodeItem, Tree},
};
use uuid::Uuid;

use crate::{error::Error, Result};

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
        Arc::new(CollectionViewTree {
            tree: Tree::from_items(collections),
        })
    }
}

#[derive(uniffi::Object)]
pub struct CollectionViewTree {
    tree: Tree<CollectionView>,
}

#[derive(uniffi::Object)]
#[allow(unused)]
pub struct CollectionViewNodeItem {
    node_item: NodeItem<CollectionView>,
}

#[uniffi::export]
impl CollectionViewTree {
    pub fn get_item_by_id(&self, collection_id: Uuid) -> Option<Arc<CollectionViewNodeItem>> {
        self.tree
            .get_item_by_id(collection_id)
            .map(|n| Arc::new(CollectionViewNodeItem { node_item: n }))
    }

    pub fn get_root_items(&self) -> Vec<Arc<CollectionViewNodeItem>> {
        self.tree
            .nodes
            .iter()
            .filter(|n| n.parent_idx.is_none())
            .filter_map(|n| self.get_item_by_id(n.item_id))
            .collect()
    }
}

#[uniffi::export]
impl CollectionViewNodeItem {
    pub fn get_item(&self) -> CollectionView {
        self.node_item.item.clone()
    }

    pub fn get_parent(&self) -> Option<CollectionView> {
        self.node_item.parent.clone()
    }

    pub fn get_children(&self) -> Vec<CollectionView> {
        self.node_item.children.clone()
    }

    pub fn get_ancestors(&self) -> HashMap<Uuid, String> {
        self.node_item.ancestors.clone()
    }
}
