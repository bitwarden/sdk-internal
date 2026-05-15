use bitwarden_api_api::models::AttachmentRequestModel;
use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError, RepositoryOption};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

use super::delete::delete_attachment;
use crate::{AttachmentsClient, Cipher, CipherId, VaultParseError, cipher::cipher::PartialCipher};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CipherCreateAttachmentError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    #[error("Server returned an unsupported file upload type")]
    UnsupportedFileUploadType,
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for CipherCreateAttachmentError {
    fn from(value: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(value.into())
    }
}

/// Where the encrypted attachment bytes should be pushed.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum FileUploadType {
    /// Upload directly to the Bitwarden server.
    Direct,
    /// Upload to Azure Blob storage via the returned presigned URL.
    Azure,
}

impl TryFrom<bitwarden_api_api::models::FileUploadType> for FileUploadType {
    type Error = CipherCreateAttachmentError;

    fn try_from(value: bitwarden_api_api::models::FileUploadType) -> Result<Self, Self::Error> {
        match value {
            bitwarden_api_api::models::FileUploadType::Direct => Ok(Self::Direct),
            bitwarden_api_api::models::FileUploadType::Azure => Ok(Self::Azure),
            bitwarden_api_api::models::FileUploadType::__Unknown(_) => {
                Err(CipherCreateAttachmentError::UnsupportedFileUploadType)
            }
        }
    }
}

/// Metadata for opening a new attachment slot on the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct CreateAttachmentRequest {
    /// Encrypted attachment key in `EncString` format.
    pub key: String,
    /// Encrypted file name in `EncString` format.
    pub file_name: String,
    /// Size of the encrypted file in bytes.
    pub file_size: i64,
    /// Revision date of the cipher when the request was prepared, used by the server
    /// to detect concurrent modifications.
    pub last_known_revision_date: String,
    /// When true, the slot is opened via the admin authorization scope. The server returns
    /// a [`bitwarden_api_api::models::CipherMiniResponseModel`] and local repository state
    /// is not modified.
    pub as_admin: bool,
}

impl From<CreateAttachmentRequest> for AttachmentRequestModel {
    fn from(value: CreateAttachmentRequest) -> Self {
        Self {
            key: Some(value.key),
            file_name: Some(value.file_name),
            file_size: Some(value.file_size),
            admin_request: Some(value.as_admin),
            last_known_revision_date: Some(value.last_known_revision_date),
        }
    }
}

/// Server-assigned data for a freshly-created attachment slot. The caller pushes the
/// encrypted bytes to [`Self::upload_url`] using the indicated [`Self::file_upload_type`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct CreatedAttachment {
    /// Server-assigned ID of the new attachment.
    pub attachment_id: String,
    /// Where the encrypted bytes should be pushed.
    pub upload_url: String,
    /// Direct (local Bitwarden server) or Azure Blob storage.
    pub file_upload_type: FileUploadType,
    /// Merged cipher returned by the server. Populated only when the slot was opened via
    /// the admin scope (`as_admin: true`) — admin operations do not modify the local
    /// repository, so the caller receives the cipher inline.
    pub cipher: Option<Cipher>,
}

/// Opens a new attachment slot on the server (POST `/ciphers/{id}/attachment/v2`) and
/// updates the local repository with the merged cipher state returned by the server.
///
/// If anything fails after the server has accepted the slot (e.g., the response is
/// malformed or the local repository write fails), the SDK makes a best-effort attempt
/// to delete the orphaned slot before returning the original error.
pub async fn create_attachment<R: Repository<Cipher> + ?Sized>(
    cipher_id: CipherId,
    request: CreateAttachmentRequest,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
) -> Result<CreatedAttachment, CipherCreateAttachmentError> {
    let as_admin = request.as_admin;
    let existing_cipher = if as_admin {
        None
    } else {
        repository.get(cipher_id).await?
    };

    let response = api_client
        .ciphers_api()
        .post_attachment(cipher_id.into(), Some(request.into()))
        .await?;

    // Extract the attachment id up front so a best-effort rollback is possible if
    // anything in the rest of the function fails.
    let new_attachment_id = response
        .attachment_id
        .clone()
        .ok_or(MissingFieldError("attachment_id"))?;

    let result = finalize_create(response, existing_cipher, cipher_id, repository, as_admin).await;

    if result.is_err() {
        let rollback = if as_admin {
            api_client
                .ciphers_api()
                .delete_attachment_admin(cipher_id.into(), &new_attachment_id)
                .await
                .map(|_| ())
                .map_err(|e| format!("{e:?}"))
        } else {
            delete_attachment(cipher_id, &new_attachment_id, api_client, repository)
                .await
                .map(|_| ())
                .map_err(|e| format!("{e:?}"))
        };

        if let Err(rollback_err) = rollback {
            tracing::warn!(
                "failed to roll back orphaned attachment slot {new_attachment_id} on cipher {cipher_id}: {rollback_err}",
            );
        }
    }

    result
}

async fn finalize_create<R: Repository<Cipher> + ?Sized>(
    response: bitwarden_api_api::models::AttachmentUploadDataResponseModel,
    existing_cipher: Option<Cipher>,
    cipher_id: CipherId,
    repository: &R,
    as_admin: bool,
) -> Result<CreatedAttachment, CipherCreateAttachmentError> {
    let cipher = if as_admin {
        let cipher_mini = response
            .cipher_mini_response
            .ok_or(MissingFieldError("cipher_mini_response"))?;
        Some((*cipher_mini).merge_with_cipher(None)?)
    } else {
        let cipher_response = response
            .cipher_response
            .ok_or(MissingFieldError("cipher_response"))?;
        let merged = (*cipher_response).merge_with_cipher(existing_cipher)?;
        repository.set(cipher_id, merged).await?;
        None
    };

    let attachment_id = response
        .attachment_id
        .ok_or(MissingFieldError("attachment_id"))?;
    let upload_url = response.url.ok_or(MissingFieldError("url"))?;
    let file_upload_type: FileUploadType = response
        .file_upload_type
        .ok_or(MissingFieldError("file_upload_type"))?
        .try_into()?;

    Ok(CreatedAttachment {
        attachment_id,
        upload_url,
        file_upload_type,
        cipher,
    })
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl AttachmentsClient {
    /// Opens a new attachment slot on the server. The caller is responsible for pushing
    /// the encrypted bytes to [`CreatedAttachment::upload_url`] using the appropriate
    /// transport for [`CreatedAttachment::file_upload_type`].
    pub async fn create_attachment(
        &self,
        cipher_id: CipherId,
        request: CreateAttachmentRequest,
    ) -> Result<CreatedAttachment, CipherCreateAttachmentError> {
        create_attachment(
            cipher_id,
            request,
            &self.api_configurations.api_client,
            self.repository.require()?.as_ref(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            AttachmentUploadDataResponseModel, CipherMiniResponseModel, CipherResponseModel,
            DeleteAttachmentResponseModel,
        },
    };
    use bitwarden_state::repository::Repository;
    use bitwarden_test::MemoryRepository;

    use super::*;
    use crate::{CipherRepromptType, CipherType};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const NEW_ATTACHMENT_ID: &str = "newatt9999999999999999999999999";
    const TEST_CIPHER_NAME: &str = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";
    const TEST_FILE_NAME: &str = "2.mV50WiLq6duhwGbhM1TO0A==|dTufWNH8YTPP0EMlNLIpFA==|QHp+7OM8xHtEmCfc9QPXJ0Ro2BeakzvLgxJZ7NdLuDc=";
    const TEST_KEY: &str = "2.6TPEiYULFg/4+3CpDRwCqw==|6swweBHCJcd5CHdwBBWuRN33XRV22VoroDFDUmiM4OzjPEAhgZK57IZS1KkBlCcFvT+t+YbsmDcdv+Lqr+iJ3MmzfJ40MCB5TfYy+22HVRA=|rkgFDh2IWTfPC1Y66h68Diiab/deyi1p/X0Fwkva0NQ=";

    fn test_request() -> CreateAttachmentRequest {
        CreateAttachmentRequest {
            key: TEST_KEY.to_string(),
            file_name: TEST_FILE_NAME.to_string(),
            file_size: 65,
            last_known_revision_date: "2024-05-31T11:20:58.4566667Z".to_string(),
            as_admin: false,
        }
    }

    fn admin_request() -> CreateAttachmentRequest {
        CreateAttachmentRequest {
            as_admin: true,
            ..test_request()
        }
    }

    fn test_cipher() -> Cipher {
        Cipher {
            id: TEST_CIPHER_ID.parse().ok(),
            name: TEST_CIPHER_NAME.parse().unwrap(),
            r#type: CipherType::Login,
            attachments: None,
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            notes: None,
            login: None,
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            bank_account: None,
            drivers_license: None,
            passport: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: true,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            fields: None,
            password_history: None,
            creation_date: "2024-05-31T11:20:58.4566667Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-05-31T11:20:58.4566667Z".parse().unwrap(),
            archived_date: None,
            data: None,
        }
    }

    fn server_cipher_response() -> CipherResponseModel {
        CipherResponseModel {
            id: Some(TEST_CIPHER_ID.try_into().unwrap()),
            name: Some(TEST_CIPHER_NAME.to_string()),
            r#type: Some(bitwarden_api_api::models::CipherType::Login),
            creation_date: Some("2024-05-31T11:20:58.4566667Z".to_string()),
            revision_date: Some("2024-05-31T11:20:58.4566667Z".to_string()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn returns_created_attachment_on_success() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_post_attachment()
                .returning(|_id, _req| {
                    Ok(AttachmentUploadDataResponseModel {
                        attachment_id: Some(NEW_ATTACHMENT_ID.to_string()),
                        url: Some("http://example.com/upload".to_string()),
                        file_upload_type: Some(bitwarden_api_api::models::FileUploadType::Direct),
                        cipher_response: Some(Box::new(server_cipher_response())),
                        cipher_mini_response: None,
                        ..Default::default()
                    })
                });
            mock.ciphers_api.expect_delete_attachment().never();
        });

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let repository = MemoryRepository::<Cipher>::default();
        repository.set(cipher_id, test_cipher()).await.unwrap();

        let result = create_attachment(cipher_id, test_request(), &api_client, &repository)
            .await
            .unwrap();

        assert_eq!(result.attachment_id, NEW_ATTACHMENT_ID);
        assert_eq!(result.upload_url, "http://example.com/upload");
        assert_eq!(result.file_upload_type, FileUploadType::Direct);

        // Repository should have the merged cipher state from the response.
        let stored = repository.get(cipher_id).await.unwrap().unwrap();
        assert_eq!(stored.id, Some(cipher_id));
    }

    #[tokio::test]
    async fn admin_returns_cipher_from_mini_response_and_skips_repository_write() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_post_attachment()
                .withf(|_id, req| req.as_ref().and_then(|r| r.admin_request).unwrap_or(false))
                .returning(|_id, _req| {
                    Ok(AttachmentUploadDataResponseModel {
                        attachment_id: Some(NEW_ATTACHMENT_ID.to_string()),
                        url: Some("http://example.com/upload".to_string()),
                        file_upload_type: Some(bitwarden_api_api::models::FileUploadType::Direct),
                        cipher_response: None,
                        cipher_mini_response: Some(Box::new(CipherMiniResponseModel {
                            id: Some(TEST_CIPHER_ID.try_into().unwrap()),
                            name: Some(TEST_CIPHER_NAME.to_string()),
                            r#type: Some(bitwarden_api_api::models::CipherType::Login),
                            creation_date: Some("2024-05-31T11:20:58.4566667Z".to_string()),
                            revision_date: Some("2024-05-31T11:20:58.4566667Z".to_string()),
                            attachments: None,
                            ..Default::default()
                        })),
                        ..Default::default()
                    })
                });
            mock.ciphers_api.expect_delete_attachment().never();
            mock.ciphers_api.expect_delete_attachment_admin().never();
        });

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let repository = MemoryRepository::<Cipher>::default();

        let result = create_attachment(cipher_id, admin_request(), &api_client, &repository)
            .await
            .unwrap();

        assert_eq!(result.attachment_id, NEW_ATTACHMENT_ID);
        assert_eq!(result.upload_url, "http://example.com/upload");
        assert!(result.cipher.is_some());
        assert_eq!(result.cipher.unwrap().id, Some(cipher_id));

        // Admin path must not write to the local repository.
        assert!(repository.get(cipher_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn admin_rolls_back_via_admin_delete_when_finalize_fails() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_post_attachment()
                .returning(|_id, _req| {
                    Ok(AttachmentUploadDataResponseModel {
                        attachment_id: Some(NEW_ATTACHMENT_ID.to_string()),
                        url: Some("http://example.com/upload".to_string()),
                        file_upload_type: Some(bitwarden_api_api::models::FileUploadType::Direct),
                        cipher_response: None,
                        cipher_mini_response: None,
                        ..Default::default()
                    })
                });
            // Admin rollback uses the admin DELETE endpoint, not the user one.
            mock.ciphers_api
                .expect_delete_attachment_admin()
                .withf(|_id, attachment_id| attachment_id == NEW_ATTACHMENT_ID)
                .times(1)
                .returning(|_id, _att_id| {
                    Ok(DeleteAttachmentResponseModel {
                        object: None,
                        cipher: None,
                    })
                });
            mock.ciphers_api.expect_delete_attachment().never();
        });

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let repository = MemoryRepository::<Cipher>::default();

        let err = create_attachment(cipher_id, admin_request(), &api_client, &repository)
            .await
            .unwrap_err();

        assert!(matches!(err, CipherCreateAttachmentError::MissingField(_)));
    }

    #[tokio::test]
    async fn rolls_back_orphaned_slot_when_response_has_no_cipher() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_post_attachment()
                .returning(|_id, _req| {
                    Ok(AttachmentUploadDataResponseModel {
                        attachment_id: Some(NEW_ATTACHMENT_ID.to_string()),
                        url: Some("http://example.com/upload".to_string()),
                        file_upload_type: Some(bitwarden_api_api::models::FileUploadType::Direct),
                        cipher_response: None,
                        cipher_mini_response: None,
                        ..Default::default()
                    })
                });
            mock.ciphers_api
                .expect_delete_attachment()
                .withf(|_id, attachment_id| attachment_id == NEW_ATTACHMENT_ID)
                .times(1)
                .returning(|_id, _att_id| {
                    Ok(DeleteAttachmentResponseModel {
                        object: None,
                        cipher: None,
                    })
                });
        });

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let repository = MemoryRepository::<Cipher>::default();
        repository.set(cipher_id, test_cipher()).await.unwrap();

        let err = create_attachment(cipher_id, test_request(), &api_client, &repository)
            .await
            .unwrap_err();

        assert!(matches!(err, CipherCreateAttachmentError::MissingField(_)));
    }

    #[tokio::test]
    async fn errors_without_rollback_when_post_v2_fails() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_post_attachment()
                .returning(|_id, _req| {
                    Err(bitwarden_api_api::apis::Error::ResponseError(
                        bitwarden_api_api::apis::ResponseContent {
                            status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                            content: "boom".to_string(),
                            entity: None,
                        },
                    ))
                });
            // No slot was opened, so no rollback should be attempted.
            mock.ciphers_api.expect_delete_attachment().never();
        });

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let repository = MemoryRepository::<Cipher>::default();
        repository.set(cipher_id, test_cipher()).await.unwrap();

        let err = create_attachment(cipher_id, test_request(), &api_client, &repository)
            .await
            .unwrap_err();

        assert!(matches!(err, CipherCreateAttachmentError::Api(_)));
    }

    #[test]
    fn file_upload_type_unknown_variant_returns_error() {
        let result: Result<FileUploadType, _> =
            bitwarden_api_api::models::FileUploadType::__Unknown(42).try_into();
        assert!(matches!(
            result,
            Err(CipherCreateAttachmentError::UnsupportedFileUploadType)
        ));
    }
}
