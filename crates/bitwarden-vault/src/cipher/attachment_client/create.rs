use bitwarden_api_api::models::AttachmentRequestModel;
use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_crypto::EncString;
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{RepositoryError, RepositoryOption};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

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

/// Where attachment bytes should be uploaded.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum AttachmentFileUploadType {
    /// Upload directly to the Bitwarden server.
    Direct,
    /// Upload to Azure Blob storage via the returned presigned URL.
    Azure,
}

impl TryFrom<bitwarden_api_api::models::FileUploadType> for AttachmentFileUploadType {
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
///
/// The caller pre-encrypts the key, file name, and contents; the SDK only opens the slot and
/// the caller uploads. See `upgrade_attachment` for the alternative where the SDK owns the
/// encryption and upload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct CreateAttachmentRequest {
    /// Encrypted attachment key.
    pub key: EncString,
    /// Encrypted file name.
    pub file_name: EncString,
    /// Encrypted file size in byte
    pub file_size: u64,
    /// Cipher revision date
    pub last_known_revision_date: DateTime<Utc>,
    /// Uses the admin auth scope. The server returns a
    /// `CipherMiniResponseModel`, and the local repository is not updated.
    pub as_admin: bool,
}

impl From<CreateAttachmentRequest> for AttachmentRequestModel {
    fn from(value: CreateAttachmentRequest) -> Self {
        Self {
            key: Some(value.key.to_string()),
            file_name: Some(value.file_name.to_string()),
            file_size: Some(value.file_size as i64),
            admin_request: Some(value.as_admin),
            last_known_revision_date: Some(
                value
                    .last_known_revision_date
                    .to_rfc3339_opts(SecondsFormat::Millis, true),
            ),
        }
    }
}

/// Server data for a newly created attachment slot. The caller uploads the
/// encrypted bytes to [`Self::upload_url`] using [`Self::file_upload_type`]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct CreatedAttachment {
    /// Server-assigned attachment ID.
    pub attachment_id: String,
    /// Upload target for the encrypted bytes
    pub upload_url: String,
    /// Bitwarden server or Azure Blob Storage.
    pub file_upload_type: AttachmentFileUploadType,
    /// Cipher returned by the server. For non-admin requests, this is also
    /// written to the local repository
    pub cipher: Cipher,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl AttachmentsClient {
    /// Creates a new attachment slot on the server and updates local repository
    /// state with the merged cipher returned by the server.
    ///
    /// The caller must upload the encrypted bytes to [`CreatedAttachment::upload_url`]
    /// using the transport in [`CreatedAttachment::file_upload_type`].
    ///
    /// If a later step fails after slot creation, the SDK best-effort deletes the
    /// orphaned slot and returns the original error.
    pub async fn create_attachment(
        &self,
        cipher_id: CipherId,
        request: CreateAttachmentRequest,
    ) -> Result<CreatedAttachment, CipherCreateAttachmentError> {
        let as_admin = request.as_admin;
        let repository = self.repository.require()?;
        let existing_cipher = if as_admin {
            None
        } else {
            repository.get(cipher_id).await?
        };

        let api_client = &self.api_configurations.api_client;
        let response = api_client
            .ciphers_api()
            .post_attachment(cipher_id.into(), Some(request.into()))
            .await?;

        // Read the attachment ID first so we can best-effort roll back
        // if anything else fails.
        let new_attachment_id = response
            .attachment_id
            .clone()
            .ok_or(MissingFieldError("attachment_id"))?;

        let result = self
            .finalize_create(response, existing_cipher, cipher_id, as_admin)
            .await;

        if result.is_err() {
            let rollback = if as_admin {
                api_client
                    .ciphers_api()
                    .delete_attachment_admin(cipher_id.into(), &new_attachment_id)
                    .await
                    .map(|_| ())
                    .map_err(|e| format!("{e:?}"))
            } else {
                api_client
                    .ciphers_api()
                    .delete_attachment(cipher_id.into(), &new_attachment_id)
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

    async fn finalize_create(
        &self,
        response: bitwarden_api_api::models::AttachmentUploadDataResponseModel,
        existing_cipher: Option<Cipher>,
        cipher_id: CipherId,
        as_admin: bool,
    ) -> Result<CreatedAttachment, CipherCreateAttachmentError> {
        let cipher = if as_admin {
            let cipher_mini = response
                .cipher_mini_response
                .ok_or(MissingFieldError("cipher_mini_response"))?;
            (*cipher_mini).merge_with_cipher(None)?
        } else {
            let cipher_response = response
                .cipher_response
                .ok_or(MissingFieldError("cipher_response"))?;
            let merged = (*cipher_response).merge_with_cipher(existing_cipher)?;
            self.repository
                .require()?
                .set(cipher_id, merged.clone())
                .await?;
            merged
        };

        let attachment_id = response
            .attachment_id
            .ok_or(MissingFieldError("attachment_id"))?;
        let upload_url = response.url.ok_or(MissingFieldError("url"))?;
        let file_upload_type: AttachmentFileUploadType = response
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
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            AttachmentUploadDataResponseModel, CipherMiniResponseModel, CipherResponseModel,
            DeleteAttachmentResponseModel,
        },
    };
    use bitwarden_core::{client::ApiConfigurations, key_management::KeySlotIds};
    use bitwarden_crypto::KeyStore;
    use bitwarden_state::repository::Repository;
    use bitwarden_test::MemoryRepository;

    use super::*;
    use crate::{CipherRepromptType, CipherType};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const NEW_ATTACHMENT_ID: &str = "newatt9999999999999999999999999";
    const TEST_CIPHER_NAME: &str = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";
    const TEST_FILE_NAME: &str = "2.mV50WiLq6duhwGbhM1TO0A==|dTufWNH8YTPP0EMlNLIpFA==|QHp+7OM8xHtEmCfc9QPXJ0Ro2BeakzvLgxJZ7NdLuDc=";
    const TEST_KEY: &str = "2.6TPEiYULFg/4+3CpDRwCqw==|6swweBHCJcd5CHdwBBWuRN33XRV22VoroDFDUmiM4OzjPEAhgZK57IZS1KkBlCcFvT+t+YbsmDcdv+Lqr+iJ3MmzfJ40MCB5TfYy+22HVRA=|rkgFDh2IWTfPC1Y66h68Diiab/deyi1p/X0Fwkva0NQ=";

    fn client_with_api_and_repo(
        api_client: ApiClient,
        repository: MemoryRepository<Cipher>,
    ) -> (AttachmentsClient, Arc<MemoryRepository<Cipher>>) {
        let repo_arc = Arc::new(repository);
        let client = AttachmentsClient {
            key_store: KeyStore::<KeySlotIds>::default(),
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
            repository: Some(repo_arc.clone()),
            http_client: reqwest::Client::new(),
        };
        (client, repo_arc)
    }

    fn test_request() -> CreateAttachmentRequest {
        CreateAttachmentRequest {
            key: TEST_KEY.parse().unwrap(),
            file_name: TEST_FILE_NAME.parse().unwrap(),
            file_size: 65,
            last_known_revision_date: "2024-05-31T11:20:58.456Z".parse().unwrap(),
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
        let (client, repo) = client_with_api_and_repo(api_client, repository);

        let result = client
            .create_attachment(cipher_id, test_request())
            .await
            .unwrap();

        assert_eq!(result.attachment_id, NEW_ATTACHMENT_ID);
        assert_eq!(result.upload_url, "http://example.com/upload");
        assert_eq!(result.file_upload_type, AttachmentFileUploadType::Direct);
        // Merged cipher is now returned inline for both paths (Comment 5).
        assert_eq!(result.cipher.id, Some(cipher_id));

        // Repository should have the merged cipher state from the response.
        let stored = repo.get(cipher_id).await.unwrap().unwrap();
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
        let (client, repo) =
            client_with_api_and_repo(api_client, MemoryRepository::<Cipher>::default());

        let result = client
            .create_attachment(cipher_id, admin_request())
            .await
            .unwrap();

        assert_eq!(result.attachment_id, NEW_ATTACHMENT_ID);
        assert_eq!(result.upload_url, "http://example.com/upload");
        assert_eq!(result.cipher.id, Some(cipher_id));

        // Admin path must not write to the local repository.
        assert!(repo.get(cipher_id).await.unwrap().is_none());
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
        let (client, _repo) =
            client_with_api_and_repo(api_client, MemoryRepository::<Cipher>::default());

        let err = client
            .create_attachment(cipher_id, admin_request())
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
        let (client, _repo) = client_with_api_and_repo(api_client, repository);

        let err = client
            .create_attachment(cipher_id, test_request())
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
                    Err(bitwarden_api_api::apis::Error::Response(
                        bitwarden_api_api::apis::ResponseContent {
                            status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                            message: "boom".to_string(),
                        },
                    ))
                });
            // No slot was opened, so no rollback should be attempted.
            mock.ciphers_api.expect_delete_attachment().never();
        });

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let repository = MemoryRepository::<Cipher>::default();
        repository.set(cipher_id, test_cipher()).await.unwrap();
        let (client, _repo) = client_with_api_and_repo(api_client, repository);

        let err = client
            .create_attachment(cipher_id, test_request())
            .await
            .unwrap_err();

        assert!(matches!(err, CipherCreateAttachmentError::Api(_)));
    }

    #[test]
    fn file_upload_type_unknown_variant_returns_error() {
        let result: Result<AttachmentFileUploadType, _> =
            bitwarden_api_api::models::FileUploadType::__Unknown(42).try_into();
        assert!(matches!(
            result,
            Err(CipherCreateAttachmentError::UnsupportedFileUploadType)
        ));
    }
}
