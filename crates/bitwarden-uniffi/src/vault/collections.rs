use std::sync::Arc;

use bitwarden_collections::{
    collection::{Collection, CollectionId, CollectionView},
    tree::{NodeItem, Tree},
};
use bitwarden_vault::collection_client::AncestorMap;

use crate::Result;

#[expect(missing_docs)]
#[derive(uniffi::Object)]
pub struct CollectionsClient(pub(crate) bitwarden_vault::collection_client::CollectionsClient);

#[uniffi::export]
impl CollectionsClient {
    /// Decrypt collection
    pub fn decrypt(&self, collection: Collection) -> Result<CollectionView> {
        Ok(self.0.decrypt(collection)?)
    }

    /// Decrypt collection list
    pub fn decrypt_list(&self, collections: Vec<Collection>) -> Result<Vec<CollectionView>> {
        Ok(self.0.decrypt_list(collections)?)
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
pub struct CollectionViewNodeItem {
    node_item: NodeItem<CollectionView>,
}

#[uniffi::export]
impl CollectionViewTree {
    pub fn get_item_for_view(
        &self,
        collection_view: CollectionView,
    ) -> Option<Arc<CollectionViewNodeItem>> {
        self.tree
            .get_item_by_id(collection_view.id.unwrap_or_default().into())
            .map(|n| Arc::new(CollectionViewNodeItem { node_item: n }))
    }

    pub fn get_root_items(&self) -> Vec<Arc<CollectionViewNodeItem>> {
        self.tree
            .get_root_items()
            .into_iter()
            .map(|n| Arc::new(CollectionViewNodeItem { node_item: n }))
            .collect()
    }

    pub fn get_flat_items(&self) -> Vec<Arc<CollectionViewNodeItem>> {
        self.tree
            .get_flat_items()
            .into_iter()
            .map(|n| Arc::new(CollectionViewNodeItem { node_item: n }))
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

    pub fn get_ancestors(&self) -> AncestorMap {
        AncestorMap {
            ancestors: self
                .node_item
                .ancestors
                .iter()
                .map(|(&uuid, name)| (CollectionId::new(uuid), name.clone()))
                .collect(),
        }
    }
}
