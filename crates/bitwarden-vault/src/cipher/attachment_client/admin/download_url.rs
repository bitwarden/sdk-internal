use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use reqwest::StatusCode;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{AttachmentAdminClient, CipherId};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CipherAdminGetAttachmentDownloadUrlError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error("Attachment not found")]
    NotFound,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl AttachmentAdminClient {
    /// Fetches the download URL for an attachment from the admin API. The admin client has
    /// no local repository to fall back to on 404, so a server-side 404 is surfaced as
    /// [`CipherAdminGetAttachmentDownloadUrlError::NotFound`] for the caller to handle.
    pub async fn get_attachment_download_url(
        &self,
        cipher_id: CipherId,
        attachment_id: String,
    ) -> Result<String, CipherAdminGetAttachmentDownloadUrlError> {
        let response = self
            .api_configurations
            .api_client
            .ciphers_api()
            .get_attachment_data_admin(cipher_id.into(), &attachment_id)
            .await
            .map_err(|e| match e {
                bitwarden_api_api::ApiError::Response(content)
                    if content.status == StatusCode::NOT_FOUND =>
                {
                    CipherAdminGetAttachmentDownloadUrlError::NotFound
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
    use bitwarden_core::client::ApiConfigurations;
    use reqwest::StatusCode;

    use super::*;

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_ATTACHMENT_ID: &str = "uf7bkexzag04d3cw04jsbqqkbpbwhxs0";
    const TEST_API_URL: &str = "http://localhost:4000/attachments/test/api";

    fn client_with_api(api_client: ApiClient) -> AttachmentAdminClient {
        AttachmentAdminClient {
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
        }
    }

    #[tokio::test]
    async fn returns_url_from_api_response() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_get_attachment_data_admin()
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

        let client = client_with_api(api_client);
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let url = client
            .get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID.to_string())
            .await
            .unwrap();

        assert_eq!(url, TEST_API_URL);
    }

    #[tokio::test]
    async fn returns_missing_field_when_response_has_no_url() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_get_attachment_data_admin()
                .returning(|_id, _attachment_id| {
                    Ok(AttachmentResponseModel {
                        id: Some(TEST_ATTACHMENT_ID.to_string()),
                        url: None,
                        ..Default::default()
                    })
                });
        });

        let client = client_with_api(api_client);
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let err = client
            .get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID.to_string())
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            CipherAdminGetAttachmentDownloadUrlError::MissingField(_)
        ));
    }

    #[tokio::test]
    async fn returns_not_found_on_404() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_get_attachment_data_admin()
                .returning(|_id, _attachment_id| {
                    Err(bitwarden_api_api::ApiError::Response(
                        bitwarden_api_api::ResponseContent {
                            status: StatusCode::NOT_FOUND,
                            message: String::new(),
                        },
                    ))
                });
        });

        let client = client_with_api(api_client);
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let err = client
            .get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID.to_string())
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            CipherAdminGetAttachmentDownloadUrlError::NotFound
        ));
    }

    #[tokio::test]
    async fn propagates_non_404_api_errors() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_get_attachment_data_admin()
                .returning(|_id, _attachment_id| {
                    Err(bitwarden_api_api::ApiError::Response(
                        bitwarden_api_api::ResponseContent {
                            status: StatusCode::INTERNAL_SERVER_ERROR,
                            message: "bitwarden".to_string(),
                        },
                    ))
                });
        });

        let client = client_with_api(api_client);
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let err = client
            .get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID.to_string())
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            CipherAdminGetAttachmentDownloadUrlError::Api(_)
        ));
    }
}
