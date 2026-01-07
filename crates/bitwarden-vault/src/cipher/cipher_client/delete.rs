use bitwarden_api_api::models::CipherBulkDeleteRequestModel;
use bitwarden_core::{ApiError, OrganizationId};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{Cipher, CipherId, CiphersClient};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum DeleteCipherError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for DeleteCipherError {
    fn from(value: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(value.into())
    }
}

async fn delete_cipher<R: Repository<Cipher> + ?Sized>(
    cipher_id: CipherId,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
) -> Result<(), DeleteCipherError> {
    let api = api_client.ciphers_api();
    api.delete(cipher_id.into()).await?;
    repository.remove(cipher_id.to_string()).await?;
    Ok(())
}

async fn delete_ciphers<R: Repository<Cipher> + ?Sized>(
    cipher_ids: Vec<CipherId>,
    organization_id: Option<OrganizationId>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
) -> Result<(), DeleteCipherError> {
    let api = api_client.ciphers_api();

    api.delete_many(Some(CipherBulkDeleteRequestModel {
        ids: cipher_ids.iter().map(|id| id.to_string()).collect(),
        organization_id: organization_id.map(|id| id.to_string()),
    }))
    .await?;

    for cipher_id in cipher_ids {
        repository.remove(cipher_id.to_string()).await?;
    }
    Ok(())
}

async fn soft_delete<R: Repository<Cipher> + ?Sized>(
    cipher_id: CipherId,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
) -> Result<(), DeleteCipherError> {
    let api = api_client.ciphers_api();
    api.put_delete(cipher_id.into()).await?;
    process_soft_delete(repository, cipher_id).await?;
    Ok(())
}

async fn soft_delete_many<R: Repository<Cipher> + ?Sized>(
    cipher_ids: Vec<CipherId>,
    organization_id: Option<OrganizationId>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
) -> Result<(), DeleteCipherError> {
    let api = api_client.ciphers_api();

    api.put_delete_many(Some(CipherBulkDeleteRequestModel {
        ids: cipher_ids.iter().map(|id| id.to_string()).collect(),
        organization_id: organization_id.map(|id| id.to_string()),
    }))
    .await?;
    for cipher_id in cipher_ids {
        process_soft_delete(repository, cipher_id).await?;
    }
    Ok(())
}

async fn process_soft_delete<R: Repository<Cipher> + ?Sized>(
    repository: &R,
    cipher_id: CipherId,
) -> Result<(), RepositoryError> {
    let cipher: Option<Cipher> = repository.get(cipher_id.to_string()).await?;
    if let Some(mut cipher) = cipher {
        cipher.soft_delete();
        repository.set(cipher_id.to_string(), cipher).await?;
    }
    Ok(())
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    /// Deletes the [Cipher] with the matching [CipherId] from the server.
    pub async fn delete(&self, cipher_id: CipherId) -> Result<(), DeleteCipherError> {
        let configs = self.client.internal.get_api_configurations().await;
        delete_cipher(cipher_id, &configs.api_client, &*self.get_repository()?).await
    }

    /// Deletes all [Cipher] objects with a matching [CipherId] from the server.
    pub async fn delete_many(
        &self,
        cipher_ids: Vec<CipherId>,
        organization_id: Option<OrganizationId>,
    ) -> Result<(), DeleteCipherError> {
        let configs = self.client.internal.get_api_configurations().await;
        delete_ciphers(
            cipher_ids,
            organization_id,
            &configs.api_client,
            &*self.get_repository()?,
        )
        .await
    }

    /// Soft-deletes the [Cipher] with the matching [CipherId] from the server.
    pub async fn soft_delete(&self, cipher_id: CipherId) -> Result<(), DeleteCipherError> {
        let configs = self.client.internal.get_api_configurations().await;
        soft_delete(cipher_id, &configs.api_client, &*self.get_repository()?).await
    }

    /// Soft-deletes all [Cipher] objects for the given [CipherId]s from the server.
    pub async fn soft_delete_many(
        &self,
        cipher_ids: Vec<CipherId>,
        organization_id: Option<OrganizationId>,
    ) -> Result<(), DeleteCipherError> {
        soft_delete_many(
            cipher_ids,
            organization_id,
            &self
                .client
                .internal
                .get_api_configurations()
                .await
                .api_client,
            &*self.get_repository()?,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::apis::ApiClient;
    use bitwarden_state::repository::Repository;
    use bitwarden_test::MemoryRepository;
    use chrono::Utc;

    use crate::{
        Cipher, CipherId,
        cipher_client::delete::{delete_cipher, delete_ciphers, soft_delete, soft_delete_many},
    };

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_CIPHER_ID_2: &str = "6faa9684-c793-4a2d-8a12-b33900187098";

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

    #[tokio::test]
    async fn test_delete() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_delete()
                .returning(move |_model| Ok(()));
        });

        // let client = create_client_with_wiremock(mock_server).await;
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let repository = MemoryRepository::<Cipher>::default();
        repository
            .set(cipher_id.to_string(), generate_test_cipher())
            .await
            .unwrap();

        delete_cipher(cipher_id, &api_client, &repository)
            .await
            .unwrap();

        let cipher = repository.get(cipher_id.to_string()).await.unwrap();
        assert!(
            cipher.is_none(),
            "Cipher is deleted from the local repository"
        );
    }

    #[tokio::test]
    async fn test_delete_many() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_delete_many()
                .returning(move |_model| Ok(()));
        });
        let repository = MemoryRepository::<Cipher>::default();

        let cipher_1 = generate_test_cipher();
        let mut cipher_2 = generate_test_cipher();
        cipher_2.id = Some(TEST_CIPHER_ID_2.parse().unwrap());

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let cipher_id_2: CipherId = TEST_CIPHER_ID_2.parse().unwrap();

        repository
            .set(cipher_id.to_string(), cipher_1)
            .await
            .unwrap();
        repository
            .set(TEST_CIPHER_ID_2.to_string(), cipher_2)
            .await
            .unwrap();

        delete_ciphers(vec![cipher_id, cipher_id_2], None, &api_client, &repository)
            .await
            .unwrap();

        let cipher_1 = repository.get(cipher_id.to_string()).await.unwrap();
        let cipher_2 = repository.get(cipher_id_2.to_string()).await.unwrap();
        assert!(
            cipher_1.is_none(),
            "Cipher is deleted from the local repository"
        );
        assert!(
            cipher_2.is_none(),
            "Cipher is deleted from the local repository"
        );
    }

    #[tokio::test]
    async fn test_soft_delete() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_put_delete()
                .returning(move |_model| Ok(()));
        });
        let repository = MemoryRepository::<Cipher>::default();

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        repository
            .set(cipher_id.to_string(), generate_test_cipher())
            .await
            .unwrap();

        let start_time = Utc::now();
        soft_delete(cipher_id, &api_client, &repository)
            .await
            .unwrap();
        let end_time = Utc::now();

        let cipher: Cipher = repository
            .get(cipher_id.to_string())
            .await
            .unwrap()
            .unwrap();
        assert!(
            cipher.deleted_date.unwrap() >= start_time && cipher.deleted_date.unwrap() <= end_time,
            "Cipher was flagged as deleted in the repository."
        );
    }

    #[tokio::test]
    async fn test_soft_delete_many() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_put_delete_many()
                .returning(move |_model| Ok(()));
        });
        let repository = MemoryRepository::<Cipher>::default();

        let cipher_1 = generate_test_cipher();
        let mut cipher_2 = generate_test_cipher();
        cipher_2.id = Some(TEST_CIPHER_ID_2.parse().unwrap());

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let cipher_id_2: CipherId = TEST_CIPHER_ID_2.parse().unwrap();
        repository
            .set(cipher_id.to_string(), cipher_1)
            .await
            .unwrap();
        repository
            .set(TEST_CIPHER_ID_2.to_string(), cipher_2)
            .await
            .unwrap();

        let start_time = Utc::now();

        soft_delete_many(vec![cipher_id, cipher_id_2], None, &api_client, &repository)
            .await
            .unwrap();
        let end_time = Utc::now();

        let cipher_1 = repository
            .get(cipher_id.to_string())
            .await
            .unwrap()
            .unwrap();
        let cipher_2 = repository
            .get(cipher_id_2.to_string())
            .await
            .unwrap()
            .unwrap();

        assert!(
            cipher_1.deleted_date.unwrap() >= start_time
                && cipher_1.deleted_date.unwrap() <= end_time,
            "Cipher was flagged as deleted in the repository."
        );
        assert!(
            cipher_2.deleted_date.unwrap() >= start_time
                && cipher_2.deleted_date.unwrap() <= end_time,
            "Cipher was flagged as deleted in the repository."
        );
    }
}
