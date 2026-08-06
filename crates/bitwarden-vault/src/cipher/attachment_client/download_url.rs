use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{RepositoryError, RepositoryOption};
use reqwest::StatusCode;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{AttachmentsClient, CipherId};

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

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl AttachmentsClient {
    /// Returns the attachment download URL.
    ///
    /// With `emergency_access_id`, uses the emergency-access endpoint and never falls back.
    /// Otherwise uses the cipher endpoint and falls back to the local repository on 404.
    pub async fn get_attachment_download_url(
        &self,
        cipher_id: CipherId,
        attachment_id: String,
        emergency_access_id: Option<String>,
    ) -> Result<String, CipherGetAttachmentDownloadUrlError> {
        if let Some(emergency_access_id) = emergency_access_id {
            return self
                .get_emergency_access_attachment_download_url(
                    &emergency_access_id,
                    cipher_id,
                    &attachment_id,
                )
                .await;
        }

        match self
            .api_configurations
            .api_client
            .ciphers_api()
            .get_attachment_data(cipher_id.into(), &attachment_id)
            .await
        {
            Ok(response) => response.url.ok_or_else(|| MissingFieldError("url").into()),
            Err(bitwarden_api_api::ApiError::Response(content))
                if content.status == StatusCode::NOT_FOUND =>
            {
                let repository = self.repository.require()?;
                let cipher = repository
                    .get(cipher_id)
                    .await?
                    .ok_or(CipherGetAttachmentDownloadUrlError::NotFound)?;

                cipher
                    .attachments
                    .and_then(|attachments| {
                        attachments
                            .into_iter()
                            .find(|a| a.id.as_deref() == Some(&attachment_id))
                    })
                    .and_then(|attachment| attachment.url)
                    .ok_or(CipherGetAttachmentDownloadUrlError::NotFound)
            }
            Err(e) => Err(e.into()),
        }
    }
}

impl AttachmentsClient {
    /// Fetches an attachment download URL via the emergency-access endpoint.
    async fn get_emergency_access_attachment_download_url(
        &self,
        emergency_access_id: &str,
        cipher_id: CipherId,
        attachment_id: &str,
    ) -> Result<String, CipherGetAttachmentDownloadUrlError> {
        let emergency_access_id = emergency_access_id
            .parse::<uuid::Uuid>()
            .map_err(|_| CipherGetAttachmentDownloadUrlError::InvalidEmergencyAccessId)?;

        let response = self
            .api_configurations
            .api_client
            .emergency_access_api()
            .get_attachment_data(emergency_access_id, cipher_id.into(), attachment_id)
            .await
            .map_err(|e| match e {
                bitwarden_api_api::ApiError::Response(content)
                    if content.status == StatusCode::NOT_FOUND =>
                {
                    CipherGetAttachmentDownloadUrlError::NotFound
                }
                other => other.into(),
            })?;

        response.url.ok_or_else(|| MissingFieldError("url").into())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::{apis::ApiClient, models::AttachmentResponseModel};
    use bitwarden_core::{client::ApiConfigurations, key_management::KeySlotIds};
    use bitwarden_crypto::KeyStore;
    use bitwarden_state::repository::Repository;
    use bitwarden_test::MemoryRepository;

    use super::*;
    use crate::{Attachment, Cipher, CipherRepromptType, CipherType};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_ATTACHMENT_ID: &str = "uf7bkexzag04d3cw04jsbqqkbpbwhxs0";
    const TEST_CIPHER_NAME: &str = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";
    const TEST_FILE_NAME: &str = "2.mV50WiLq6duhwGbhM1TO0A==|dTufWNH8YTPP0EMlNLIpFA==|QHp+7OM8xHtEmCfc9QPXJ0Ro2BeakzvLgxJZ7NdLuDc=";
    const TEST_API_URL: &str = "http://localhost:4000/attachments/test/api";
    const TEST_FALLBACK_URL: &str = "http://localhost:4000/attachments/test/fallback";
    const TEST_EMERGENCY_ACCESS_ID: &str = "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d";

    fn client_with_api_and_repo(
        api_client: ApiClient,
        repository: MemoryRepository<Cipher>,
    ) -> AttachmentsClient {
        AttachmentsClient {
            key_store: KeyStore::<KeySlotIds>::default(),
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
            repository: Some(Arc::new(repository)),
            http_client: reqwest::Client::new(),
        }
    }

    fn test_cipher() -> Cipher {
        Cipher {
            id: TEST_CIPHER_ID.parse().ok(),
            name: Some(TEST_CIPHER_NAME.parse().unwrap()),
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

    fn not_found_response() -> bitwarden_api_api::ApiError {
        bitwarden_api_api::ApiError::Response(bitwarden_api_api::ResponseContent {
            status: StatusCode::NOT_FOUND,
            message: String::new(),
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

        let client = client_with_api_and_repo(api_client, MemoryRepository::<Cipher>::default());
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let url = client
            .get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID.to_string(), None)
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

        let client = client_with_api_and_repo(api_client, MemoryRepository::<Cipher>::default());
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let err = client
            .get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID.to_string(), None)
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

        let client = client_with_api_and_repo(api_client, repository);

        let url = client
            .get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID.to_string(), None)
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

        let client = client_with_api_and_repo(api_client, MemoryRepository::<Cipher>::default());
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let err = client
            .get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID.to_string(), None)
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

        let client = client_with_api_and_repo(api_client, repository);

        let err = client
            .get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID.to_string(), None)
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
                    Err(bitwarden_api_api::ApiError::Response(
                        bitwarden_api_api::ResponseContent {
                            status: StatusCode::INTERNAL_SERVER_ERROR,
                            message: "bitwarden".to_string(),
                        },
                    ))
                });
        });

        let client = client_with_api_and_repo(api_client, MemoryRepository::<Cipher>::default());
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let err = client
            .get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID.to_string(), None)
            .await
            .unwrap_err();

        assert!(matches!(err, CipherGetAttachmentDownloadUrlError::Api(_)));
    }

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

        let client = client_with_api_and_repo(api_client, MemoryRepository::<Cipher>::default());
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let url = client
            .get_attachment_download_url(
                cipher_id,
                TEST_ATTACHMENT_ID.to_string(),
                Some(TEST_EMERGENCY_ACCESS_ID.to_string()),
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

        let client = client_with_api_and_repo(api_client, MemoryRepository::<Cipher>::default());
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let err = client
            .get_attachment_download_url(
                cipher_id,
                TEST_ATTACHMENT_ID.to_string(),
                Some(TEST_EMERGENCY_ACCESS_ID.to_string()),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            CipherGetAttachmentDownloadUrlError::MissingField(_)
        ));
    }

    #[tokio::test]
    async fn emergency_access_returns_not_found_on_404() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.emergency_access_api
                .expect_get_attachment_data()
                .returning(|_ea_id, _cipher_id, _attachment_id| Err(not_found_response()));
        });

        let client = client_with_api_and_repo(api_client, MemoryRepository::<Cipher>::default());
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let err = client
            .get_attachment_download_url(
                cipher_id,
                TEST_ATTACHMENT_ID.to_string(),
                Some(TEST_EMERGENCY_ACCESS_ID.to_string()),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, CipherGetAttachmentDownloadUrlError::NotFound));
    }

    #[tokio::test]
    async fn emergency_access_propagates_non_404_api_errors() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.emergency_access_api
                .expect_get_attachment_data()
                .returning(|_ea_id, _cipher_id, _attachment_id| {
                    Err(bitwarden_api_api::ApiError::Response(
                        bitwarden_api_api::ResponseContent {
                            status: StatusCode::INTERNAL_SERVER_ERROR,
                            message: "bitwarden".to_string(),
                        },
                    ))
                });
        });

        let client = client_with_api_and_repo(api_client, MemoryRepository::<Cipher>::default());
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let err = client
            .get_attachment_download_url(
                cipher_id,
                TEST_ATTACHMENT_ID.to_string(),
                Some(TEST_EMERGENCY_ACCESS_ID.to_string()),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, CipherGetAttachmentDownloadUrlError::Api(_)));
    }

    #[tokio::test]
    async fn returns_invalid_emergency_access_id_when_parse_fails() {
        let api_client = ApiClient::new_mocked(|_mock| {});
        let client = client_with_api_and_repo(api_client, MemoryRepository::<Cipher>::default());
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let err = client
            .get_attachment_download_url(
                cipher_id,
                TEST_ATTACHMENT_ID.to_string(),
                Some("not-a-uuid".to_string()),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            CipherGetAttachmentDownloadUrlError::InvalidEmergencyAccessId
        ));
    }
}
