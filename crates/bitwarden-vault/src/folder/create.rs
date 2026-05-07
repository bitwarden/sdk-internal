use bitwarden_api_api::models::FolderRequestModel;
use bitwarden_core::{
    ApiError, MissingFieldError,
    key_management::{KeySlotIds, SymmetricKeySlotId},
    require,
};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, IdentifyKey, KeyStoreContext, PrimitiveEncryptable,
};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{RepositoryError, RepositoryOption};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{Folder, FolderView, FoldersClient, VaultParseError};

/// Request to add or edit a folder.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct FolderAddEditRequest {
    /// The new name of the folder.
    pub name: String,
}

impl CompositeEncryptable<KeySlotIds, SymmetricKeySlotId, FolderRequestModel>
    for FolderAddEditRequest
{
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<FolderRequestModel, CryptoError> {
        Ok(FolderRequestModel {
            name: self.name.encrypt(ctx, key)?.to_string(),
        })
    }
}

impl IdentifyKey<SymmetricKeySlotId> for FolderAddEditRequest {
    fn key_identifier(&self) -> SymmetricKeySlotId {
        SymmetricKeySlotId::User
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

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl FoldersClient {
    /// Create a new [Folder] and save it to the server.
    pub async fn create(
        &self,
        request: FolderAddEditRequest,
    ) -> Result<FolderView, CreateFolderError> {
        let folder_request = self.key_store.encrypt(request)?;

        let resp = self
            .api_configurations
            .api_client
            .folders_api()
            .post(Some(folder_request))
            .await
            .map_err(ApiError::from)?;

        let folder: Folder = resp.try_into()?;

        self.repository
            .require()?
            .set(require!(folder.id), folder.clone())
            .await?;

        Ok(self.key_store.decrypt(&folder)?)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::{apis::ApiClient, models::FolderResponseModel};
    use bitwarden_core::{
        client::ApiConfigurations, key_management::create_test_crypto_with_user_key,
    };
    use bitwarden_crypto::SymmetricCryptoKey;
    use bitwarden_test::MemoryRepository;
    use uuid::uuid;

    use super::*;
    use crate::FolderId;

    fn create_client(api_client: ApiClient) -> FoldersClient {
        FoldersClient {
            key_store: create_test_crypto_with_user_key(
                SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
            ),
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
            repository: Some(Arc::new(MemoryRepository::<Folder>::default())),
        }
    }

    #[tokio::test]
    async fn test_create_folder() {
        let folder_id = FolderId::new(uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1"));

        let client = create_client(ApiClient::new_mocked(move |mock| {
            mock.folders_api
                .expect_post()
                .returning(move |model| {
                    Ok(FolderResponseModel {
                        id: Some(folder_id.into()),
                        name: Some(model.unwrap().name),
                        revision_date: Some("2025-01-01T00:00:00Z".to_string()),
                        object: Some("folder".to_string()),
                    })
                })
                .once();
        }));

        let result = client
            .create(FolderAddEditRequest {
                name: "test".to_string(),
            })
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

        // Confirm the folder was stored in the repository
        assert_eq!(
            client
                .key_store
                .decrypt(
                    &client
                        .repository
                        .as_ref()
                        .unwrap()
                        .get(folder_id)
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
        let client = create_client(ApiClient::new_mocked(move |mock| {
            mock.folders_api.expect_post().returning(move |_model| {
                Err(bitwarden_api_api::apis::Error::Io(std::io::Error::other(
                    "Simulated error",
                )))
            });
        }));

        let result = client
            .create(FolderAddEditRequest {
                name: "test".to_string(),
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CreateFolderError::Api(_)));
    }
}
