use bitwarden_api_api::models::CipherBulkDeleteRequestModel;
use bitwarden_core::{ApiError, OrganizationId};
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{CipherId, cipher_client::admin::CipherAdminClient};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
/// Errors that can occur when deleting ciphers as an admin.
pub enum DeleteCipherAdminError {
    // ApiError is incompatible with wasm_bindgen, so we wrap it in this enum
    // for wasm_bindgen compatibility.
    #[error(transparent)]
    Api(#[from] ApiError),
}

async fn delete_cipher(
    cipher_id: CipherId,
    api_client: &bitwarden_api_api::apis::ApiClient,
) -> Result<(), ApiError> {
    let api = api_client.ciphers_api();
    api.delete_admin(cipher_id.into()).await?;
    Ok(())
}

async fn delete_ciphers_many(
    cipher_ids: Vec<CipherId>,
    organization_id: OrganizationId,
    api_client: &bitwarden_api_api::apis::ApiClient,
) -> Result<(), ApiError> {
    let api = api_client.ciphers_api();

    api.delete_many_admin(Some(CipherBulkDeleteRequestModel {
        ids: cipher_ids.iter().map(|id| id.to_string()).collect(),
        organization_id: Some(organization_id.to_string()),
    }))
    .await?;

    Ok(())
}

async fn soft_delete(
    cipher_id: CipherId,
    api_client: &bitwarden_api_api::apis::ApiClient,
) -> Result<(), ApiError> {
    let api = api_client.ciphers_api();
    api.put_delete_admin(cipher_id.into()).await?;
    Ok(())
}

async fn soft_delete_many(
    cipher_ids: Vec<CipherId>,
    organization_id: OrganizationId,
    api_client: &bitwarden_api_api::apis::ApiClient,
) -> Result<(), ApiError> {
    let api = api_client.ciphers_api();

    api.put_delete_many_admin(Some(CipherBulkDeleteRequestModel {
        ids: cipher_ids.iter().map(|id| id.to_string()).collect(),
        organization_id: Some(organization_id.to_string()),
    }))
    .await?;
    Ok(())
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CipherAdminClient {
    /// Deletes the Cipher with the matching CipherId from the server, using the admin endpoint.
    /// Affects server data only, does not modify local state.
    pub async fn delete(&self, cipher_id: CipherId) -> Result<(), DeleteCipherAdminError> {
        Ok(delete_cipher(
            cipher_id,
            &self.client.internal.get_api_configurations().api_client,
        )
        .await?)
    }

    /// Soft-deletes the Cipher with the matching CipherId from the server, using the admin
    /// endpoint. Affects server data only, does not modify local state.
    pub async fn soft_delete(&self, cipher_id: CipherId) -> Result<(), DeleteCipherAdminError> {
        Ok(soft_delete(
            cipher_id,
            &self.client.internal.get_api_configurations().api_client,
        )
        .await?)
    }

    /// Deletes all Cipher objects with a matching CipherId from the server, using the admin
    /// endpoint. Affects server data only, does not modify local state.
    pub async fn delete_many(
        &self,
        cipher_ids: Vec<CipherId>,
        organization_id: OrganizationId,
    ) -> Result<(), DeleteCipherAdminError> {
        Ok(delete_ciphers_many(
            cipher_ids,
            organization_id,
            &self.client.internal.get_api_configurations().api_client,
        )
        .await?)
    }

    /// Soft-deletes all Cipher objects for the given CipherIds from the server, using the admin
    /// endpoint. Affects server data only, does not modify local state.
    pub async fn soft_delete_many(
        &self,
        cipher_ids: Vec<CipherId>,
        organization_id: OrganizationId,
    ) -> Result<(), DeleteCipherAdminError> {
        Ok(soft_delete_many(
            cipher_ids,
            organization_id,
            &self.client.internal.get_api_configurations().api_client,
        )
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_CIPHER_ID_2: &str = "6faa9684-c793-4a2d-8a12-b33900187098";
    const TEST_ORG_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";

    #[tokio::test]
    async fn test_delete_as_admin() {
        delete_cipher(
            TEST_CIPHER_ID.parse().unwrap(),
            &bitwarden_api_api::apis::ApiClient::new_mocked(|mock| {
                mock.ciphers_api.expect_delete_admin().returning(move |id| {
                    assert_eq!(&id.to_string(), TEST_CIPHER_ID);
                    Ok(())
                });
            }),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn test_soft_delete_as_admin() {
        soft_delete(
            TEST_CIPHER_ID.parse().unwrap(),
            &bitwarden_api_api::apis::ApiClient::new_mocked(|mock| {
                mock.ciphers_api
                    .expect_put_delete_admin()
                    .returning(move |id| {
                        assert_eq!(&id.to_string(), TEST_CIPHER_ID);
                        Ok(())
                    });
            }),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn test_delete_many_as_admin() {
        delete_ciphers_many(
            vec![
                TEST_CIPHER_ID.parse().unwrap(),
                TEST_CIPHER_ID_2.parse().unwrap(),
            ],
            TEST_ORG_ID.parse().unwrap(),
            &bitwarden_api_api::apis::ApiClient::new_mocked(|mock| {
                mock.ciphers_api
                    .expect_delete_many_admin()
                    .returning(move |request| {
                        let CipherBulkDeleteRequestModel {
                            ids,
                            organization_id,
                        } = request.unwrap();

                        assert_eq!(
                            ids,
                            vec![TEST_CIPHER_ID.to_string(), TEST_CIPHER_ID_2.to_string(),],
                        );
                        assert_eq!(organization_id, Some(TEST_ORG_ID.to_string()));
                        Ok(())
                    });
            }),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn test_soft_delete_many_as_admin() {
        soft_delete_many(
            vec![
                TEST_CIPHER_ID.parse().unwrap(),
                TEST_CIPHER_ID_2.parse().unwrap(),
            ],
            TEST_ORG_ID.parse().unwrap(),
            &bitwarden_api_api::apis::ApiClient::new_mocked(|mock| {
                mock.ciphers_api
                    .expect_put_delete_many_admin()
                    .returning(move |request| {
                        let CipherBulkDeleteRequestModel {
                            ids,
                            organization_id,
                        } = request.unwrap();

                        assert_eq!(
                            ids,
                            vec![TEST_CIPHER_ID.to_string(), TEST_CIPHER_ID_2.to_string()],
                        );
                        assert_eq!(organization_id, Some(TEST_ORG_ID.to_string()));
                        Ok(())
                    });
            }),
        )
        .await
        .unwrap()
    }
}
