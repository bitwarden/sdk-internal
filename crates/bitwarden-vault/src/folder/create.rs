use bitwarden_api_api::models::FolderRequestModel;
use bitwarden_core::{
    ApiError, MissingFieldError,
    key_management::{KeyIds, SymmetricKeyId},
    require,
};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, IdentifyKey, KeyStore, KeyStoreContext, PrimitiveEncryptable,
};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{Folder, FolderView, VaultParseError};

/// Request to add or edit a folder.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct FolderAddEditRequest {
    /// The new name of the folder.
    pub name: String,
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, FolderRequestModel> for FolderAddEditRequest {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<FolderRequestModel, CryptoError> {
        Ok(FolderRequestModel {
            name: self.name.encrypt(ctx, key)?.to_string(),
        })
    }
}

impl IdentifyKey<SymmetricKeyId> for FolderAddEditRequest {
    fn key_identifier(&self) -> SymmetricKeyId {
        SymmetricKeyId::User
    }
}

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CreateFolderError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub(super) async fn create_folder<R: Repository<Folder> + ?Sized>(
    key_store: &KeyStore<KeyIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    request: FolderAddEditRequest,
) -> Result<FolderView, CreateFolderError> {
    let folder_request = key_store.encrypt(request)?;

    let resp = api_client
        .folders_api()
        .post(Some(folder_request))
        .await
        .map_err(ApiError::from)?;

    let folder: Folder = resp.try_into()?;

    repository
        .set(require!(folder.id).to_string(), folder.clone())
        .await?;

    Ok(key_store.decrypt(&folder)?)
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::FolderResponseModel};
    use bitwarden_crypto::SymmetricCryptoKey;
    use bitwarden_test::MemoryRepository;
    use uuid::uuid;

    use super::*;
    use crate::FolderId;

    #[tokio::test]
    async fn test_create_folder() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let folder_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.folders_api
                .expect_post()
                .returning(move |model| {
                    Ok(FolderResponseModel {
                        id: Some(folder_id),
                        name: Some(model.unwrap().name),
                        revision_date: Some("2025-01-01T00:00:00Z".to_string()),
                        object: Some("folder".to_string()),
                    })
                })
                .once();
        });

        let repository = MemoryRepository::<Folder>::default();

        let result = create_folder(
            &store,
            &api_client,
            &repository,
            FolderAddEditRequest {
                name: "test".to_string(),
            },
        )
        .await
        .unwrap();

        assert_eq!(
            result,
            FolderView {
                id: Some(FolderId::new(folder_id)),
                name: "test".to_string(),
                revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
            }
        );

        // Confirm the folder was stored in the repository
        assert_eq!(
            store
                .decrypt(
                    &repository
                        .get(folder_id.to_string())
                        .await
                        .unwrap()
                        .unwrap()
                )
                .unwrap(),
            result
        );
    }

    #[tokio::test]
    async fn test_create_folder_http_error() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.folders_api.expect_post().returning(move |_model| {
                Err(bitwarden_api_api::apis::Error::Io(std::io::Error::other(
                    "Simulated error",
                )))
            });
        });

        let repository = MemoryRepository::<Folder>::default();

        let result = create_folder(
            &store,
            &api_client,
            &repository,
            FolderAddEditRequest {
                name: "test".to_string(),
            },
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CreateFolderError::Api(_)));
    }
}
