use std::collections::HashMap;

use bitwarden_collections::{
    collection::{Collection, CollectionId, CollectionView},
    tree::{NodeItem, Tree},
};
use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{DecryptError, EncryptError};

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Clone)]
pub struct CollectionsClient {
    pub(crate) client: Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CollectionsClient {
    #[allow(missing_docs)]
    pub fn encrypt(&self, collection_view: CollectionView) -> Result<Collection, EncryptError> {
        let key_store = self.client.internal.get_key_store();
        let collection = key_store.encrypt(collection_view)?;
        Ok(collection)
    }

    #[allow(missing_docs)]
    pub fn encrypt_list(
        &self,
        collection_views: Vec<CollectionView>,
    ) -> Result<Vec<Collection>, EncryptError> {
        let key_store = self.client.internal.get_key_store();
        let collections = key_store.encrypt_list(&collection_views)?;
        Ok(collections)
    }

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

#[cfg_attr(
    feature = "wasm",
    derive(Tsify, Serialize, Deserialize),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AncestorMap {
    pub ancestors: HashMap<CollectionId, String>,
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

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CollectionViewTree {
    pub fn get_item_for_view(
        &self,
        collection_view: CollectionView,
    ) -> Option<CollectionViewNodeItem> {
        self.tree
            .get_item_by_id(collection_view.id.unwrap_or_default().into())
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
    use bitwarden_collections::collection::CollectionType;
    use bitwarden_core::client::test_accounts::test_bitwarden_com_account;

    use super::*;
    use crate::VaultClientExt;

    fn test_collection() -> Collection {
        Collection {
            id: Some("66c5ca57-0868-4c7e-902f-b181009709c0".parse().unwrap()),
            organization_id: "1bc9ac1e-f5aa-45f2-94bf-b181009709b8".parse().unwrap(),
            name: "2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI=".parse().unwrap(),
            external_id: None,
            hide_passwords: false,
            read_only: false,
            manage: false,
            default_user_collection_email: None,
            r#type: CollectionType::SharedCollection,
        }
    }

    #[tokio::test]
    async fn test_decrypt_list() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let dec = client
            .vault()
            .collections()
            .decrypt_list(vec![test_collection()])
            .unwrap();

        assert_eq!(dec[0].name, "Default collection");
    }

    #[tokio::test]
    async fn test_decrypt() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let dec = client
            .vault()
            .collections()
            .decrypt(test_collection())
            .unwrap();

        assert_eq!(dec.name, "Default collection");
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let view = client
            .vault()
            .collections()
            .decrypt(test_collection())
            .unwrap();

        assert_eq!(view.name, "Default collection");

        // Re-encrypt the decrypted view, then decrypt again
        let expected_id = view.id;
        let expected_org_id = view.organization_id;
        let re_encrypted = client.vault().collections().encrypt(view).unwrap();
        let re_decrypted = client.vault().collections().decrypt(re_encrypted).unwrap();

        assert_eq!(re_decrypted.name, "Default collection");
        assert_eq!(re_decrypted.id, expected_id);
        assert_eq!(re_decrypted.organization_id, expected_org_id);
    }

    #[tokio::test]
    async fn test_encrypt_list_decrypt_list_roundtrip() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let views = client
            .vault()
            .collections()
            .decrypt_list(vec![test_collection()])
            .unwrap();

        assert_eq!(views.len(), 1);
        assert_eq!(views[0].name, "Default collection");

        let expected_id = views[0].id;
        let expected_org_id = views[0].organization_id;

        let re_encrypted = client.vault().collections().encrypt_list(views).unwrap();

        assert_eq!(re_encrypted.len(), 1);

        let re_decrypted = client
            .vault()
            .collections()
            .decrypt_list(re_encrypted)
            .unwrap();

        assert_eq!(re_decrypted.len(), 1);
        assert_eq!(re_decrypted[0].name, "Default collection");
        assert_eq!(re_decrypted[0].id, expected_id);
        assert_eq!(re_decrypted[0].organization_id, expected_org_id);
    }
}
