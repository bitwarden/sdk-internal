use bitwarden_collections::{
    collection::{Collection, CollectionView},
    tree::{NodeItem, Tree},
};
use bitwarden_core::Client;
use bitwarden_error::js_sys::Map;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::DecryptError;

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Clone)]
pub struct CollectionsClient {
    pub(crate) client: Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CollectionsClient {
    #[allow(missing_docs)]
    pub fn decrypt(&self, collection: Collection) -> Result<CollectionView, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        let view = key_store.decrypt(&collection)?;
        Ok(view)
    }

    #[allow(missing_docs)]
    pub fn decrypt_list(
        &self,
        collections: Vec<Collection>,
    ) -> Result<Vec<CollectionView>, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        let views = key_store.decrypt_list(&collections)?;
        Ok(views)
    }

    ///
    /// Returns the vector of CollectionView objects in a tree structure based on its implemented
    /// path().
    pub fn get_collection_tree(&self, collections: Vec<CollectionView>) -> CollectionViewTree {
        CollectionViewTree {
            tree: Tree::from_items(collections),
        }
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct CollectionViewTree {
    tree: Tree<CollectionView>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct CollectionViewNodeItem {
    node_item: NodeItem<CollectionView>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
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

    pub fn get_ancestors(&self) -> Map {
        self.node_item
            .ancestors
            .iter()
            .fold(Map::new(), |map, (id, name)| {
                map.set(&id.to_string().into(), &name.into());
                map
            })
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CollectionViewTree {
    pub fn get_item_by_id(
        &self,
        collection_view: CollectionView,
    ) -> Option<CollectionViewNodeItem> {
        self.tree
            .get_item_by_id(collection_view.id.unwrap_or_default())
            .map(|n| CollectionViewNodeItem { node_item: n })
    }

    pub fn get_root_items(&self) -> Vec<CollectionViewNodeItem> {
        self.tree
            .get_root_items()
            .into_iter()
            .map(|n| CollectionViewNodeItem { node_item: n })
            .collect()
    }

    pub fn get_flat_items(&self) -> Vec<CollectionViewNodeItem> {
        self.tree
            .get_flat_items()
            .into_iter()
            .map(|n| CollectionViewNodeItem { node_item: n })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::client::test_accounts::test_bitwarden_com_account;

    use super::*;
    use crate::VaultClientExt;

    #[tokio::test]
    async fn test_decrypt_list() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let dec = client.vault().collections().decrypt_list(vec![Collection {
            id: Some("66c5ca57-0868-4c7e-902f-b181009709c0".parse().unwrap()),
            organization_id: "1bc9ac1e-f5aa-45f2-94bf-b181009709b8".parse().unwrap(),
            name: "2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI=".parse().unwrap(),
            external_id: None,
            hide_passwords: false,
            read_only: false,
            manage: false,
        }]).unwrap();

        assert_eq!(dec[0].name, "Default collection");
    }

    #[tokio::test]
    async fn test_decrypt() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let dec = client.vault().collections().decrypt(Collection {
            id: Some("66c5ca57-0868-4c7e-902f-b181009709c0".parse().unwrap()),
            organization_id: "1bc9ac1e-f5aa-45f2-94bf-b181009709b8".parse().unwrap(),
            name: "2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI=".parse().unwrap(),
            external_id: None,
            hide_passwords: false,
            read_only: false,
            manage: false,
        }).unwrap();

        assert_eq!(dec.name, "Default collection");
    }
}
