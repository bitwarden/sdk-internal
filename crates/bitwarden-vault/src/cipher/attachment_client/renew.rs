use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{AttachmentsClient, CipherId};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CipherRenewFileUploadUrlError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl AttachmentsClient {
    /// Returns a renewed upload URL for an attachment.
    /// Does not modify the attachment slot.
    pub async fn renew_file_upload_url(
        &self,
        cipher_id: CipherId,
        attachment_id: String,
    ) -> Result<String, CipherRenewFileUploadUrlError> {
        let response = self
            .api_configurations
            .api_client
            .ciphers_api()
            .renew_file_upload_url(cipher_id.into(), &attachment_id)
            .await?;

        response.url.ok_or_else(|| MissingFieldError("url").into())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::{apis::ApiClient, models::AttachmentUploadDataResponseModel};
    use bitwarden_core::{client::ApiConfigurations, key_management::KeySlotIds};
    use bitwarden_crypto::KeyStore;
    use reqwest::StatusCode;

    use super::*;

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_ATTACHMENT_ID: &str = "uf7bkexzag04d3cw04jsbqqkbpbwhxs0";
    const TEST_RENEW_URL: &str = "http://localhost:4000/attachments/test/renewed";

    fn client_with_api(api_client: ApiClient) -> AttachmentsClient {
        AttachmentsClient {
            key_store: KeyStore::<KeySlotIds>::default(),
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
            repository: None,
            http_client: reqwest::Client::new(),
        }
    }

    #[tokio::test]
    async fn returns_url_from_api_response() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_renew_file_upload_url()
                .returning(|id, attachment_id| {
                    assert_eq!(&id.to_string(), TEST_CIPHER_ID);
                    assert_eq!(attachment_id, TEST_ATTACHMENT_ID);
                    Ok(AttachmentUploadDataResponseModel {
                        url: Some(TEST_RENEW_URL.to_string()),
                        ..Default::default()
                    })
                });
        });

        let client = client_with_api(api_client);
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let url = client
            .renew_file_upload_url(cipher_id, TEST_ATTACHMENT_ID.to_string())
            .await
            .unwrap();

        assert_eq!(url, TEST_RENEW_URL);
    }

    #[tokio::test]
    async fn returns_missing_field_when_response_has_no_url() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_renew_file_upload_url()
                .returning(|_id, _attachment_id| {
                    Ok(AttachmentUploadDataResponseModel {
                        url: None,
                        ..Default::default()
                    })
                });
        });

        let client = client_with_api(api_client);
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let err = client
            .renew_file_upload_url(cipher_id, TEST_ATTACHMENT_ID.to_string())
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            CipherRenewFileUploadUrlError::MissingField(_)
        ));
    }

    #[tokio::test]
    async fn propagates_api_errors() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_renew_file_upload_url()
                .returning(|_id, _attachment_id| {
                    Err(bitwarden_api_api::ApiError::Response(
                        bitwarden_api_api::ResponseContent {
                            status: StatusCode::INTERNAL_SERVER_ERROR,
                            message: "boom".to_string(),
                        },
                    ))
                });
        });

        let client = client_with_api(api_client);
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let err = client
            .renew_file_upload_url(cipher_id, TEST_ATTACHMENT_ID.to_string())
            .await
            .unwrap_err();

        assert!(matches!(err, CipherRenewFileUploadUrlError::Api(_)));
    }
}
