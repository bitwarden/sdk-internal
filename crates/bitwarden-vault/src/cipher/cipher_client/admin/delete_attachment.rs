use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{CipherId, cipher_client::admin::CipherAdminClient};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum DeleteAttachmentAdminError {
    #[error(transparent)]
    Api(#[from] ApiError),
}

async fn delete_attachment(
    cipher_id: CipherId,
    attachment_id: &str,
    api_client: &bitwarden_api_api::apis::ApiClient,
) -> Result<(), ApiError> {
    let api = api_client.ciphers_api();
    api.delete_attachment_admin(cipher_id.into(), attachment_id)
        .await?;
    Ok(())
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CipherAdminClient {
    /// Deletes an attachment from a cipher using the admin endpoint.
    /// Affects server data only, does not modify local state.
    pub async fn delete_attachment(
        &self,
        cipher_id: CipherId,
        attachment_id: String,
    ) -> Result<(), DeleteAttachmentAdminError> {
        Ok(delete_attachment(
            cipher_id,
            &attachment_id,
            &self.client.internal.get_api_configurations().api_client,
        )
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_ATTACHMENT_ID: &str = "uf7bkexzag04d3cw04jsbqqkbpbwhxs0";

    #[tokio::test]
    async fn test_delete_attachment_as_admin() {
        delete_attachment(
            TEST_CIPHER_ID.parse().unwrap(),
            TEST_ATTACHMENT_ID,
            &bitwarden_api_api::apis::ApiClient::new_mocked(|mock| {
                mock.ciphers_api.expect_delete_attachment_admin().returning(
                    move |id, attachment_id| {
                        assert_eq!(&id.to_string(), TEST_CIPHER_ID);
                        assert_eq!(attachment_id, TEST_ATTACHMENT_ID);
                        Ok(Default::default())
                    },
                );
            }),
        )
        .await
        .unwrap()
    }
}
