use bitwarden_api_api::models::CipherBulkMoveRequestModel;
use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{RepositoryError, RepositoryOption};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{CipherId, CiphersClient, FolderId};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum MoveCipherError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for MoveCipherError {
    fn from(value: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(value.into())
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    /// Moves multiple [`Cipher`](crate::Cipher) objects to a folder, or clears their folder when
    /// `folder_id` is `None`.
    pub async fn move_many(
        &self,
        cipher_ids: Vec<CipherId>,
        folder_id: Option<FolderId>,
    ) -> Result<(), MoveCipherError> {
        self.api_configurations
            .api_client
            .ciphers_api()
            .move_many(Some(CipherBulkMoveRequestModel {
                ids: cipher_ids.iter().map(|id| id.to_string()).collect(),
                folder_id: folder_id.map(|id| id.to_string()),
            }))
            .await?;

        let repository = self.repository.require()?;

        let mut updated_ciphers = Vec::new();
        for cipher_id in cipher_ids {
            if let Some(mut cipher) = repository.get(cipher_id).await? {
                cipher.folder_id = folder_id;
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
    use bitwarden_core::{
        client::ApiConfigurations, key_management::create_test_crypto_with_user_key,
    };
    use bitwarden_crypto::SymmetricCryptoKey;
    use bitwarden_state::repository::Repository;
    use bitwarden_test::MemoryRepository;

    use crate::{Cipher, CipherId, CiphersClient, FolderId};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_CIPHER_ID_2: &str = "6faa9684-c793-4a2d-8a12-b33900187098";
    const TEST_FOLDER_ID: &str = "7faa9684-c793-4a2d-8a12-b33900187099";

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

    #[tokio::test]
    async fn test_move_many_updates_folder_id() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api.expect_move_many().returning(|_| Ok(()));
        });

        let (client, repository) = create_test_client(api_client);

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let cipher_id_2: CipherId = TEST_CIPHER_ID_2.parse().unwrap();
        let folder_id: FolderId = TEST_FOLDER_ID.parse().unwrap();

        repository
            .set(cipher_id, generate_test_cipher())
            .await
            .unwrap();
        let mut cipher_2 = generate_test_cipher();
        cipher_2.id = Some(cipher_id_2);
        repository.set(cipher_id_2, cipher_2).await.unwrap();

        client
            .move_many(vec![cipher_id, cipher_id_2], Some(folder_id))
            .await
            .unwrap();

        let c1: Cipher = repository.get(cipher_id).await.unwrap().unwrap();
        let c2: Cipher = repository.get(cipher_id_2).await.unwrap().unwrap();
        assert_eq!(c1.folder_id, Some(folder_id));
        assert_eq!(c2.folder_id, Some(folder_id));
    }

    #[tokio::test]
    async fn test_move_many_clears_folder_id() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api.expect_move_many().returning(|_| Ok(()));
        });

        let (client, repository) = create_test_client(api_client);

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let folder_id: FolderId = TEST_FOLDER_ID.parse().unwrap();

        let mut cipher = generate_test_cipher();
        cipher.folder_id = Some(folder_id);
        repository.set(cipher_id, cipher).await.unwrap();

        client.move_many(vec![cipher_id], None).await.unwrap();

        let c: Cipher = repository.get(cipher_id).await.unwrap().unwrap();
        assert!(c.folder_id.is_none());
    }

    #[tokio::test]
    async fn test_move_many_skips_missing_ciphers() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api.expect_move_many().returning(|_| Ok(()));
        });

        let (client, _repository) = create_test_client(api_client);
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let folder_id: FolderId = TEST_FOLDER_ID.parse().unwrap();

        let result = client.move_many(vec![cipher_id], Some(folder_id)).await;
        assert!(result.is_ok());
    }
}
