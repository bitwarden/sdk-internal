use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
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
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for CipherAdminGetAttachmentDownloadUrlError {
    fn from(value: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(value.into())
    }
}

/// Fetches the download URL for an attachment from the admin API
pub async fn get_attachment_download_url(
    cipher_id: CipherId,
    attachment_id: &str,
    api_client: &bitwarden_api_api::apis::ApiClient,
) -> Result<String, CipherAdminGetAttachmentDownloadUrlError> {
    let response = api_client
        .ciphers_api()
        .get_attachment_data_admin(cipher_id.into(), attachment_id)
        .await?;

    response.url.ok_or_else(|| MissingFieldError("url").into())
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl AttachmentAdminClient {
    /// Returns a download URL for the given attachment via the admin server endpoint.
    /// Does not fall back to local repository state on 404.
    pub async fn get_attachment_download_url(
        &self,
        cipher_id: CipherId,
        attachment_id: String,
    ) -> Result<String, CipherAdminGetAttachmentDownloadUrlError> {
        get_attachment_download_url(
            cipher_id,
            &attachment_id,
            &self.api_configurations.api_client,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::AttachmentResponseModel};
    use reqwest::StatusCode;

    use super::*;

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_ATTACHMENT_ID: &str = "uf7bkexzag04d3cw04jsbqqkbpbwhxs0";
    const TEST_API_URL: &str = "http://localhost:4000/attachments/test/api";

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

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let url = get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID, &api_client)
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

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let err = get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID, &api_client)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            CipherAdminGetAttachmentDownloadUrlError::MissingField(_)
        ));
    }

    #[tokio::test]
    async fn propagates_api_errors() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_get_attachment_data_admin()
                .returning(|_id, _attachment_id| {
                    Err(bitwarden_api_api::apis::Error::ResponseError(
                        bitwarden_api_api::apis::ResponseContent {
                            status: StatusCode::NOT_FOUND,
                            content: String::new(),
                            entity: None,
                        },
                    ))
                });
        });

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let err = get_attachment_download_url(cipher_id, TEST_ATTACHMENT_ID, &api_client)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            CipherAdminGetAttachmentDownloadUrlError::Api(_)
        ));
    }
}
