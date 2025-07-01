use std::sync::Arc;

use bitwarden_api_api::{apis::folders_api, models::FolderRequestModel};
use bitwarden_core::{
    key_management::{KeyIds, SymmetricKeyId},
    require, ApiError, MissingFieldError,
};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, IdentifyKey, KeyStore, KeyStoreContext, PrimitiveEncryptable,
};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify_next::Tsify;
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
    RepositoryError(#[from] RepositoryError),
}

pub(super) async fn create_folder<R: Repository<Folder> + ?Sized>(
    key_store: &KeyStore<KeyIds>,
    api_config: &bitwarden_api_api::apis::configuration::Configuration,
    repository: &Arc<R>,
    request: FolderAddEditRequest,
) -> Result<FolderView, CreateFolderError> {
    let folder_request = key_store.encrypt(request)?;
    let resp = folders_api::folders_post(api_config, Some(folder_request))
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
    use bitwarden_api_api::models::FolderResponseModel;
    use bitwarden_crypto::SymmetricCryptoKey;
    use bitwarden_state::repository::MemoryRepository;
    use uuid::uuid;
    use wiremock::{matchers, Mock, MockServer, Request, ResponseTemplate};

    #[tokio::test]
    async fn test_create_folder() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/folders"))
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

        let result = create_folder(&store, api_config, &repository, request)
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
