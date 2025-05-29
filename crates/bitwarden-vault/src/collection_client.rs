use bitwarden_core::Client;

use crate::{error::DecryptError, Collection, CollectionView};

pub struct CollectionsClient {
    pub(crate) client: Client,
}

impl CollectionsClient {
    pub fn decrypt(&self, collection: Collection) -> Result<CollectionView, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        let view = key_store.decrypt(&collection)?;
        Ok(view)
    }

    pub fn decrypt_list(
        &self,
        collections: Vec<Collection>,
    ) -> Result<Vec<CollectionView>, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        let views = key_store.decrypt_list(&collections)?;
        Ok(views)
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
