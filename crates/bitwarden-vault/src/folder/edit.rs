use bitwarden_api_api::apis::folders_api;
use bitwarden_core::{key_management::KeyIds, ApiError, MissingFieldError};
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{Folder, FolderAddEditRequest, FolderView, ItemNotFoundError, VaultParseError};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EditFolderError {
    #[error(transparent)]
    ItemNotFound(#[from] ItemNotFoundError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    RepositoryError(#[from] RepositoryError),
    #[error(transparent)]
    Uuid(#[from] uuid::Error),
}

pub(super) async fn edit_folder<R: Repository<Folder> + ?Sized>(
    key_store: &KeyStore<KeyIds>,
    api_config: &bitwarden_api_api::apis::configuration::Configuration,
    repository: &R,
    folder_id: &str,
    request: FolderAddEditRequest,
) -> Result<FolderView, EditFolderError> {
    // Verify the folder we're updating exists
    repository
        .get(folder_id.to_owned())
        .await?
        .ok_or(ItemNotFoundError)?;

    let folder_request = key_store.encrypt(request)?;

    let resp = folders_api::folders_id_put(api_config, folder_id, Some(folder_request))
        .await
        .map_err(ApiError::from)?;

    let folder: Folder = resp.try_into()?;

    debug_assert!(folder.id.unwrap_or_default().to_string() == folder_id);

    repository
        .set(folder_id.to_string(), folder.clone())
        .await?;

    Ok(key_store.decrypt(&folder)?)
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::configuration::Configuration,
        models::{FolderRequestModel, FolderResponseModel},
    };
    use bitwarden_core::key_management::SymmetricKeyId;
    use bitwarden_crypto::{PrimitiveEncryptable, SymmetricCryptoKey};
    use bitwarden_test::{start_api_mock, MemoryRepository};
    use uuid::uuid;
    use wiremock::{matchers, Mock, Request, ResponseTemplate};

    use super::*;

    async fn repository_add_folder(
        repository: &MemoryRepository<Folder>,
        store: &KeyStore<KeyIds>,
        folder_id: uuid::Uuid,
        name: &str,
    ) {
        repository
            .set(
                folder_id.to_string(),
                Folder {
                    id: Some(folder_id),
                    name: name
                        .encrypt(&mut store.context(), SymmetricKeyId::User)
                        .unwrap(),
                    revision_date: "2024-01-01T00:00:00Z".parse().unwrap(),
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_edit_folder() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let folder_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");

        let (_server, api_config) = start_api_mock(vec![Mock::given(matchers::path(format!(
            "/folders/{}",
            folder_id
        )))
        .respond_with(move |req: &Request| {
            let body: FolderRequestModel = req.body_json().unwrap();
            ResponseTemplate::new(200).set_body_json(FolderResponseModel {
                object: Some("folder".to_string()),
                id: Some(folder_id),
                name: Some(body.name),
                revision_date: Some("2025-01-01T00:00:00Z".to_string()),
            })
        })
        .expect(1)])
        .await;

        let repository = MemoryRepository::<Folder>::default();
        repository_add_folder(&repository, &store, folder_id, "old_name").await;

        let result = edit_folder(
            &store,
            &api_config,
            &repository,
            &folder_id.to_string(),
            FolderAddEditRequest {
                name: "test".to_string(),
            },
        )
        .await
        .unwrap();

        assert_eq!(
            result,
            FolderView {
                id: Some(folder_id),
                name: "test".to_string(),
                revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
            }
        );
    }

    #[tokio::test]
    async fn test_edit_folder_does_not_exist() {
        let store: KeyStore<KeyIds> = KeyStore::default();

        let repository = MemoryRepository::<Folder>::default();
        let folder_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");

        let result = edit_folder(
            &store,
            &Configuration::default(),
            &repository,
            &folder_id.to_string(),
            FolderAddEditRequest {
                name: "test".to_string(),
            },
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EditFolderError::ItemNotFound(_)
        ));
    }

    #[tokio::test]
    async fn test_edit_folder_http_error() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let folder_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");

        let (_server, api_config) = start_api_mock(vec![Mock::given(matchers::path(format!(
            "/folders/{}",
            folder_id
        )))
        .respond_with(ResponseTemplate::new(500))])
        .await;

        let repository = MemoryRepository::<Folder>::default();
        repository_add_folder(&repository, &store, folder_id, "old_name").await;

        let result = edit_folder(
            &store,
            &api_config,
            &repository,
            &folder_id.to_string(),
            FolderAddEditRequest {
                name: "test".to_string(),
            },
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EditFolderError::Api(_)));
    }
}
