use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    Cipher, CipherId, VaultParseError, cipher::cipher::PartialCipher,
    cipher_client::admin::CipherAdminClient,
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum DeleteAttachmentAdminError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for DeleteAttachmentAdminError {
    fn from(value: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(value.into())
    }
}

async fn delete_attachment(
    cipher_id: CipherId,
    attachment_id: &str,
    api_client: &bitwarden_api_api::apis::ApiClient,
) -> Result<Cipher, DeleteAttachmentAdminError> {
    let api = api_client.ciphers_api();
    let response = api
        .delete_attachment_admin(cipher_id.into(), attachment_id)
        .await?;

    let cipher_response = response
        .cipher
        .map(|c| *c)
        .ok_or(MissingFieldError("cipher"))?;
    Ok(cipher_response.merge_with_cipher(None)?)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CipherAdminClient {
    /// Deletes an attachment from a cipher using the admin endpoint.
    /// Affects server data only, does not modify local state.
    pub async fn delete_attachment(
        &self,
        cipher_id: CipherId,
        attachment_id: String,
    ) -> Result<Cipher, DeleteAttachmentAdminError> {
        delete_attachment(
            cipher_id,
            &attachment_id,
            &self.client.internal.get_api_configurations().api_client,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::{CipherMiniResponseModel, DeleteAttachmentResponseModel};

    use super::*;

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_ATTACHMENT_ID: &str = "uf7bkexzag04d3cw04jsbqqkbpbwhxs0";

    #[tokio::test]
    async fn test_delete_attachment_as_admin() {
        let result = delete_attachment(
            TEST_CIPHER_ID.parse().unwrap(),
            TEST_ATTACHMENT_ID,
            &bitwarden_api_api::apis::ApiClient::new_mocked(|mock| {
                mock.ciphers_api.expect_delete_attachment_admin().returning(
                    move |id, attachment_id| {
                        assert_eq!(&id.to_string(), TEST_CIPHER_ID);
                        assert_eq!(attachment_id, TEST_ATTACHMENT_ID);
                        Ok(DeleteAttachmentResponseModel {
                            object: None,
                            cipher: Some(Box::new(CipherMiniResponseModel {
                                id: Some(TEST_CIPHER_ID.try_into().unwrap()),
                                name: Some("2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=".to_string()),
                                r#type: Some(bitwarden_api_api::models::CipherType::Login),
                                creation_date: Some("2024-05-31T11:20:58.4566667Z".to_string()),
                                revision_date: Some("2024-05-31T11:20:58.4566667Z".to_string()),
                                attachments: None,
                                ..Default::default()
                            })),
                        })
                    },
                );
            }),
        )
        .await
        .unwrap();

        assert!(result.attachments.is_none());
    }
}
