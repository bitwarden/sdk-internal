use std::collections::HashSet;

use bitwarden_api_api::models::CipherBulkUpdateCollectionsRequestModel;
use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{ApiError, OrganizationId};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{RepositoryError, RepositoryOption};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{CipherId, CiphersClient};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum BulkUpdateCollectionsCipherError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for BulkUpdateCollectionsCipherError {
    fn from(value: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(value.into())
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    /// Updates collection membership for multiple [Cipher] objects.
    ///
    /// When `remove_collections` is `true`, the given collection IDs are removed from each cipher.
    /// When `false`, they are added without introducing duplicates.
    pub async fn bulk_update_collections(
        &self,
        organization_id: OrganizationId,
        cipher_ids: Vec<CipherId>,
        collection_ids: Vec<CollectionId>,
        remove_collections: bool,
    ) -> Result<(), BulkUpdateCollectionsCipherError> {
        self.api_configurations
            .api_client
            .ciphers_api()
            .post_bulk_collections(Some(CipherBulkUpdateCollectionsRequestModel {
                organization_id: Some(organization_id.into()),
                cipher_ids: Some(cipher_ids.iter().map(|id| (*id).into()).collect()),
                collection_ids: Some(collection_ids.iter().map(|id| (*id).into()).collect()),
                remove_collections: Some(remove_collections),
            }))
            .await?;

        let repository = self.repository.require()?;
        let mut updated_ciphers = Vec::new();
        for cipher_id in cipher_ids {
            if let Some(mut cipher) = repository.get(cipher_id).await? {
                if remove_collections {
                    cipher
                        .collection_ids
                        .retain(|id| !collection_ids.contains(id));
                } else {
                    cipher.collection_ids = cipher
                        .collection_ids
                        .into_iter()
                        .chain(collection_ids.iter().copied())
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .collect();
                }
                updated_ciphers.push((cipher_id, cipher));
            }
        }
        repository.set_bulk(updated_ciphers).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::apis::ApiClient;
    use bitwarden_collections::collection::CollectionId;
    use bitwarden_core::{
        OrganizationId, client::ApiConfigurations, key_management::create_test_crypto_with_user_key,
    };
    use bitwarden_crypto::SymmetricCryptoKey;
    use bitwarden_state::repository::Repository;
    use bitwarden_test::MemoryRepository;

    use crate::{Cipher, CipherId, CiphersClient};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_ORG_ID: &str = "7faa9684-c793-4a2d-8a12-b33900187099";
    const TEST_COLLECTION_ID_1: &str = "8faa9684-c793-4a2d-8a12-b33900187100";

    fn generate_test_cipher() -> Cipher {
        Cipher {
            id: TEST_CIPHER_ID.parse().ok(),
            name: "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=".parse().unwrap(),
            r#type: crate::CipherType::Login,
            notes: Default::default(),
            organization_id: Default::default(),
            folder_id: Default::default(),
            favorite: Default::default(),
            reprompt: Default::default(),
            fields: Default::default(),
            collection_ids: Default::default(),
            key: Default::default(),
            login: Default::default(),
            identity: Default::default(),
            card: Default::default(),
            secure_note: Default::default(),
            ssh_key: Default::default(),
            bank_account: Default::default(),
            organization_use_totp: Default::default(),
            edit: Default::default(),
            permissions: Default::default(),
            view_password: Default::default(),
            local_data: Default::default(),
            attachments: Default::default(),
            password_history: Default::default(),
            creation_date: Default::default(),
            deleted_date: Default::default(),
            revision_date: Default::default(),
            archived_date: Default::default(),
            data: Default::default(),
        }
    }

    fn create_test_client(api_client: ApiClient) -> (CiphersClient, Arc<MemoryRepository<Cipher>>) {
        let repository = Arc::new(MemoryRepository::<Cipher>::default());
        #[allow(deprecated)]
        let client = CiphersClient {
            key_store: create_test_crypto_with_user_key(
                SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
            ),
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
            repository: Some(repository.clone() as Arc<dyn Repository<Cipher>>),
            client: bitwarden_core::Client::new_test(None),
        };
        (client, repository)
    }

    fn make_api_client() -> ApiClient {
        ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_post_bulk_collections()
                .returning(|_| Ok(()));
        })
    }

    #[tokio::test]
    async fn test_bulk_update_adds_collections() {
        let (client, repository) = create_test_client(make_api_client());

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let org_id: OrganizationId = TEST_ORG_ID.parse().unwrap();
        let collection_id: CollectionId = TEST_COLLECTION_ID_1.parse().unwrap();

        repository
            .set(cipher_id, generate_test_cipher())
            .await
            .unwrap();

        client
            .bulk_update_collections(org_id, vec![cipher_id], vec![collection_id], false)
            .await
            .unwrap();

        let c: Cipher = repository.get(cipher_id).await.unwrap().unwrap();
        assert!(c.collection_ids.contains(&collection_id));
    }

    #[tokio::test]
    async fn test_bulk_update_removes_collections() {
        let (client, repository) = create_test_client(make_api_client());

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let org_id: OrganizationId = TEST_ORG_ID.parse().unwrap();
        let collection_id: CollectionId = TEST_COLLECTION_ID_1.parse().unwrap();

        let mut cipher = generate_test_cipher();
        cipher.collection_ids = vec![collection_id];
        repository.set(cipher_id, cipher).await.unwrap();

        client
            .bulk_update_collections(org_id, vec![cipher_id], vec![collection_id], true)
            .await
            .unwrap();

        let c: Cipher = repository.get(cipher_id).await.unwrap().unwrap();
        assert!(!c.collection_ids.contains(&collection_id));
    }

    #[tokio::test]
    async fn test_bulk_update_no_duplicates_when_adding() {
        let (client, repository) = create_test_client(make_api_client());

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let org_id: OrganizationId = TEST_ORG_ID.parse().unwrap();
        let collection_id: CollectionId = TEST_COLLECTION_ID_1.parse().unwrap();

        let mut cipher = generate_test_cipher();
        cipher.collection_ids = vec![collection_id];
        repository.set(cipher_id, cipher).await.unwrap();

        client
            .bulk_update_collections(org_id, vec![cipher_id], vec![collection_id], false)
            .await
            .unwrap();

        let c: Cipher = repository.get(cipher_id).await.unwrap().unwrap();
        assert_eq!(
            c.collection_ids.len(),
            1,
            "no duplicates introduced when collection already present"
        );
    }

    #[tokio::test]
    async fn test_bulk_update_skips_missing_ciphers() {
        let (client, _repository) = create_test_client(make_api_client());

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let org_id: OrganizationId = TEST_ORG_ID.parse().unwrap();
        let collection_id: CollectionId = TEST_COLLECTION_ID_1.parse().unwrap();

        let result = client
            .bulk_update_collections(org_id, vec![cipher_id], vec![collection_id], false)
            .await;
        assert!(result.is_ok());
    }
}
