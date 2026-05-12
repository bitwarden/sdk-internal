use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError, RepositoryOption};
use reqwest::StatusCode;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{AttachmentsClient, Cipher, CipherId};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CipherGetAttachmentDownloadUrlError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error("Cipher or attachment not found")]
    NotFound,
    #[error("Invalid emergency access ID")]
    InvalidEmergencyAccessId,
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for CipherGetAttachmentDownloadUrlError {
    fn from(value: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(value.into())
    }
}

/// Fetches the download URL for an attachment from the API. When the server returns 404,
/// falls back to the URL stored on the cipher's attachment metadata in the local repository.
pub async fn get_attachment_download_url<R: Repository<Cipher> + ?Sized>(
    cipher_id: CipherId,
    attachment_id: &str,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
) -> Result<String, CipherGetAttachmentDownloadUrlError> {
    let api = api_client.ciphers_api();

    match api
        .get_attachment_data(cipher_id.into(), attachment_id)
        .await
    {
        Ok(response) => response.url.ok_or_else(|| MissingFieldError("url").into()),
        Err(bitwarden_api_api::apis::Error::ResponseError(content))
            if content.status == StatusCode::NOT_FOUND =>
        {
            fallback_url_from_repository(cipher_id, attachment_id, repository).await
        }
        Err(e) => Err(e.into()),
    }
}

async fn fallback_url_from_repository<R: Repository<Cipher> + ?Sized>(
    cipher_id: CipherId,
    attachment_id: &str,
    repository: &R,
) -> Result<String, CipherGetAttachmentDownloadUrlError> {
    let cipher = repository
        .get(cipher_id)
        .await?
        .ok_or(CipherGetAttachmentDownloadUrlError::NotFound)?;

    cipher
        .attachments
        .and_then(|attachments| {
            attachments
                .into_iter()
                .find(|a| a.id.as_deref() == Some(attachment_id))
        })
        .and_then(|attachment| attachment.url)
        .ok_or(CipherGetAttachmentDownloadUrlError::NotFound)
}

/// Fetches the download URL for an attachment via the emergency-access endpoint, used when
/// the grantee is viewing the grantor's cipher. The SDK has no local repository for the
/// grantor's ciphers, so this function does not fall back to a stored URL on 404 — the caller
/// is responsible for handling that fallback.
pub async fn get_emergency_access_attachment_download_url(
    emergency_access_id: uuid::Uuid,
    cipher_id: CipherId,
    attachment_id: &str,
    api_client: &bitwarden_api_api::apis::ApiClient,
) -> Result<String, CipherGetAttachmentDownloadUrlError> {
    let response = api_client
        .emergency_access_api()
        .get_attachment_data(emergency_access_id, cipher_id.into(), attachment_id)
        .await?;
    response.url.ok_or_else(|| MissingFieldError("url").into())
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl AttachmentsClient {
    /// Returns a download URL for the given attachment.
    ///
    /// When `emergency_access_id` is provided, hits the emergency-access endpoint and does
    /// not fall back to local repository state on 404. Otherwise hits the regular cipher
    /// endpoint and falls back to the URL stored on the cipher's attachment metadata in the
    /// local repository on 404.
    pub async fn get_attachment_download_url(
        &self,
        cipher_id: CipherId,
        attachment_id: String,
        emergency_access_id: Option<String>,
    ) -> Result<String, CipherGetAttachmentDownloadUrlError> {
        if let Some(ea_id) = emergency_access_id {
            let ea_id = ea_id
                .parse::<uuid::Uuid>()
                .map_err(|_| CipherGetAttachmentDownloadUrlError::InvalidEmergencyAccessId)?;
            return get_emergency_access_attachment_download_url(
                ea_id,
                cipher_id,
                &attachment_id,
                &self.api_configurations.api_client,
            )
            .await;
        }

        get_attachment_download_url(
            cipher_id,
            &attachment_id,
            &self.api_configurations.api_client,
            self.repository.require()?.as_ref(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::AttachmentResponseModel};
    use bitwarden_state::repository::Repository;
    use bitwarden_test::MemoryRepository;

    use super::*;
    use crate::{Attachment, CipherRepromptType, CipherType};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_ATTACHMENT_ID: &str = "uf7bkexzag04d3cw04jsbqqkbpbwhxs0";
    const TEST_CIPHER_NAME: &str = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";
    const TEST_FILE_NAME: &str = "2.mV50WiLq6duhwGbhM1TO0A==|dTufWNH8YTPP0EMlNLIpFA==|QHp+7OM8xHtEmCfc9QPXJ0Ro2BeakzvLgxJZ7NdLuDc=";
    const TEST_API_URL: &str = "http://localhost:4000/attachments/test/api";
    const TEST_FALLBACK_URL: &str = "http://localhost:4000/attachments/test/fallback";

    fn test_cipher() -> Cipher {
        Cipher {
            id: TEST_CIPHER_ID.parse().ok(),
            name: TEST_CIPHER_NAME.parse().unwrap(),
            r#type: CipherType::Login,
            attachments: Some(vec![Attachment {
                id: Some(TEST_ATTACHMENT_ID.to_string()),
                url: Some(TEST_FALLBACK_URL.to_string()),
                file_name: Some(TEST_FILE_NAME.parse().unwrap()),
                key: None,
                size: Some("65".to_string()),
                size_name: Some("65 Bytes".to_string()),
            }]),
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

    fn not_found_response() -> bitwarden_api_api::apis::Error<()> {
        bitwarden_api_api::apis::Error::ResponseError(bitwarden_api_api::apis::ResponseContent {
            status: StatusCode::NOT_FOUND,
            content: String::new(),
            entity: None,
        })
    }

    #[tokio::test]
    async fn returns_url_from_api_response() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_get_attachment_data()
                .returning(|id, attachment_id| {
                    assert_eq!(&id.to_string(), TEST_CIPHER_ID);
                    assert_eq!(attachment_id, TEST_ATTACHMENT_ID);
                    Ok(AttachmentResponseModel {
                        id: Some(TEST_ATTACHMENT_ID.to_string()),
                        url: Some(TEST_API_URL.to_string()),
                        ..Default::default()
                    })
                });
        });

        let repository = MemoryRepository::<Cipher>::default();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let url =
            get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID, &api_client, &repository)
                .await
                .unwrap();

        assert_eq!(url, TEST_API_URL);
    }

    #[tokio::test]
    async fn returns_missing_field_when_response_has_no_url() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_get_attachment_data()
                .returning(|_id, _attachment_id| {
                    Ok(AttachmentResponseModel {
                        id: Some(TEST_ATTACHMENT_ID.to_string()),
                        url: None,
                        ..Default::default()
                    })
                });
        });

        let repository = MemoryRepository::<Cipher>::default();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let err =
            get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID, &api_client, &repository)
                .await
                .unwrap_err();

        assert!(matches!(
            err,
            CipherGetAttachmentDownloadUrlError::MissingField(_)
        ));
    }

    #[tokio::test]
    async fn falls_back_to_repository_url_on_404() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_get_attachment_data()
                .returning(|_id, _attachment_id| Err(not_found_response()));
        });

        let repository = MemoryRepository::<Cipher>::default();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        repository.set(cipher_id, test_cipher()).await.unwrap();

        let url =
            get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID, &api_client, &repository)
                .await
                .unwrap();

        assert_eq!(url, TEST_FALLBACK_URL);
    }

    #[tokio::test]
    async fn returns_not_found_on_404_when_cipher_missing_from_repository() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_get_attachment_data()
                .returning(|_id, _attachment_id| Err(not_found_response()));
        });

        let repository = MemoryRepository::<Cipher>::default();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let err =
            get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID, &api_client, &repository)
                .await
                .unwrap_err();

        assert!(matches!(err, CipherGetAttachmentDownloadUrlError::NotFound));
    }

    #[tokio::test]
    async fn returns_not_found_on_404_when_attachment_has_no_stored_url() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_get_attachment_data()
                .returning(|_id, _attachment_id| Err(not_found_response()));
        });

        let repository = MemoryRepository::<Cipher>::default();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let mut cipher = test_cipher();
        if let Some(attachments) = cipher.attachments.as_mut() {
            for attachment in attachments {
                attachment.url = None;
            }
        }
        repository.set(cipher_id, cipher).await.unwrap();

        let err =
            get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID, &api_client, &repository)
                .await
                .unwrap_err();

        assert!(matches!(err, CipherGetAttachmentDownloadUrlError::NotFound));
    }

    #[tokio::test]
    async fn propagates_non_404_api_errors() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_get_attachment_data()
                .returning(|_id, _attachment_id| {
                    Err(bitwarden_api_api::apis::Error::ResponseError(
                        bitwarden_api_api::apis::ResponseContent {
                            status: StatusCode::INTERNAL_SERVER_ERROR,
                            content: "boom".to_string(),
                            entity: None,
                        },
                    ))
                });
        });

        let repository = MemoryRepository::<Cipher>::default();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let err =
            get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID, &api_client, &repository)
                .await
                .unwrap_err();

        assert!(matches!(err, CipherGetAttachmentDownloadUrlError::Api(_)));
    }

    const TEST_EMERGENCY_ACCESS_ID: &str = "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d";

    #[tokio::test]
    async fn emergency_access_returns_url_from_api_response() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.emergency_access_api
                .expect_get_attachment_data()
                .returning(|ea_id, cipher_id, attachment_id| {
                    assert_eq!(&ea_id.to_string(), TEST_EMERGENCY_ACCESS_ID);
                    assert_eq!(&cipher_id.to_string(), TEST_CIPHER_ID);
                    assert_eq!(attachment_id, TEST_ATTACHMENT_ID);
                    Ok(AttachmentResponseModel {
                        id: Some(TEST_ATTACHMENT_ID.to_string()),
                        url: Some(TEST_API_URL.to_string()),
                        ..Default::default()
                    })
                });
        });

        let emergency_access_id: uuid::Uuid = TEST_EMERGENCY_ACCESS_ID.parse().unwrap();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let url = get_emergency_access_attachment_download_url(
            emergency_access_id,
            cipher_id,
            TEST_ATTACHMENT_ID,
            &api_client,
        )
        .await
        .unwrap();

        assert_eq!(url, TEST_API_URL);
    }

    #[tokio::test]
    async fn emergency_access_returns_missing_field_when_response_has_no_url() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.emergency_access_api
                .expect_get_attachment_data()
                .returning(|_ea_id, _cipher_id, _attachment_id| {
                    Ok(AttachmentResponseModel {
                        id: Some(TEST_ATTACHMENT_ID.to_string()),
                        url: None,
                        ..Default::default()
                    })
                });
        });

        let emergency_access_id: uuid::Uuid = TEST_EMERGENCY_ACCESS_ID.parse().unwrap();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let err = get_emergency_access_attachment_download_url(
            emergency_access_id,
            cipher_id,
            TEST_ATTACHMENT_ID,
            &api_client,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            CipherGetAttachmentDownloadUrlError::MissingField(_)
        ));
    }

    #[tokio::test]
    async fn emergency_access_propagates_api_errors() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.emergency_access_api
                .expect_get_attachment_data()
                .returning(|_ea_id, _cipher_id, _attachment_id| {
                    Err(bitwarden_api_api::apis::Error::ResponseError(
                        bitwarden_api_api::apis::ResponseContent {
                            status: StatusCode::NOT_FOUND,
                            content: String::new(),
                            entity: None,
                        },
                    ))
                });
        });

        let emergency_access_id: uuid::Uuid = TEST_EMERGENCY_ACCESS_ID.parse().unwrap();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let err = get_emergency_access_attachment_download_url(
            emergency_access_id,
            cipher_id,
            TEST_ATTACHMENT_ID,
            &api_client,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, CipherGetAttachmentDownloadUrlError::Api(_)));
    }
}
