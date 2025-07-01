use std::sync::Arc;

use bitwarden_api_api::apis::folders_api;
use bitwarden_core::{key_management::KeyIds, require, ApiError, MissingFieldError};
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{Folder, FolderAddEditRequest, FolderView, VaultParseError};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EditFolderError {
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
    repository: &Arc<R>,
    folder_id: &str,
    request: FolderAddEditRequest,
) -> Result<FolderView, EditFolderError> {
    // Check if the folder exists
    repository
        .get(folder_id.to_owned())
        .await?
        .ok_or(MissingFieldError("Folder not found in repository"))?;

    let folder_request = key_store.encrypt(request)?;

    let resp = folders_api::folders_id_put(api_config, folder_id, Some(folder_request))
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
    use super::*;
    use bitwarden_api_api::models::{FolderRequestModel, FolderResponseModel};
    use bitwarden_core::key_management::SymmetricKeyId;
    use bitwarden_crypto::{PrimitiveEncryptable, SymmetricCryptoKey};
    use bitwarden_state::repository::MemoryRepository;
    use uuid::uuid;
    use wiremock::{matchers, Mock, MockServer, Request, ResponseTemplate};

    //#[tokio::test]
    async fn test_edit_folder() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        #[allow(deprecated)]
        let _ = ctx.set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let folder_id = "25afb11c-9c95-4db5-8bac-c21cb204a3f1".to_owned();

        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path(
                    "/folders/25afb11c-9c95-4db5-8bac-c21cb204a3f1",
                ))
                .respond_with(|req: &Request| {
                    let body: FolderRequestModel = req.body_json().unwrap();
                    ResponseTemplate::new(201).set_body_json(FolderResponseModel {
                        id: Some(uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1")),
                        name: Some(body.name),
                        revision_date: Some("2025-01-01T00:00:00Z".to_string()),
                        object: Some("folder".to_string()),
                    })
                })
                .expect(1),
            )
            .await;

        let request = FolderAddEditRequest {
            name: "test".to_string(),
        };
        let api_config = &bitwarden_api_api::apis::configuration::Configuration {
            base_path: server.uri(),
            user_agent: Some("test-agent".to_string()),
            client: reqwest::Client::new(),
            basic_auth: None,
            oauth_access_token: None,
            bearer_access_token: None,
            api_key: None,
        };
        let repository = Arc::new(MemoryRepository::<Folder>::new());

        repository
            .set(
                folder_id,
                Folder {
                    id: Some(uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1")),
                    name: "old_name".encrypt(&mut ctx, SymmetricKeyId::User).unwrap(),
                    revision_date: "2024-01-01T00:00:00Z".parse().unwrap(),
                },
            )
            .await
            .unwrap();

        let result = edit_folder(
            &store,
            api_config,
            &repository,
            "25afb11c-9c95-4db5-8bac-c21cb204a3f1",
            request,
        )
        .await
        .unwrap();

        assert_eq!(
            result,
            FolderView {
                id: Some(uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1")),
                name: "test".to_string(),
                revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
            }
        );
    }
}
