use bitwarden_api_api::models::CipherBulkDeleteRequestModel;
use bitwarden_core::OrganizationId;

use crate::{CipherError, CipherId, CiphersClient};

impl CiphersClient {
    pub async fn delete(&self, cipher_id: CipherId, as_admin: bool) -> Result<(), CipherError> {
        let configs = self.get_api_configurations().await;
        let api = configs.api_client.ciphers_api();
        if as_admin {
            api.delete_admin(cipher_id.into()).await.unwrap(); // TODO: Map errors properly.
        } else {
            api.delete(cipher_id.into()).await.unwrap();
        };
        Ok(())
    }

    pub async fn delete_many(
        &self,
        cipher_ids: Vec<CipherId>,
        organization_id: Option<OrganizationId>,
        as_admin: bool,
    ) -> Result<(), CipherError> {
        let configs = self.get_api_configurations().await;
        let api = configs.api_client.ciphers_api();
        if as_admin {
            api.delete_many_admin(Some(CipherBulkDeleteRequestModel {
                ids: cipher_ids.into_iter().map(|id| id.to_string()).collect(),
                organization_id: organization_id.map(|id| id.to_string()),
            }))
            .await
            .unwrap(); // TODO: Map errors properly.
        } else {
            api.delete_many(Some(CipherBulkDeleteRequestModel {
                ids: cipher_ids.into_iter().map(|id| id.to_string()).collect(),
                organization_id: organization_id.map(|id| id.to_string()),
            }))
            .await
            .unwrap(); // TODO: Map errors properly.
        };
        Ok(())
    }

    pub async fn soft_delete(
        &self,
        cipher_id: CipherId,
        as_admin: bool,
    ) -> Result<(), CipherError> {
        let configs = self.get_api_configurations().await;
        let api = configs.api_client.ciphers_api();
        if as_admin {
            api.put_delete_admin(cipher_id.into()).await.unwrap(); // TODO: Map errors properly.
        } else {
            api.put_delete(cipher_id.into()).await.unwrap();
        };
        Ok(())
    }

    pub async fn soft_delete_many(
        &self,
        cipher_ids: Vec<CipherId>,
        organization_id: Option<OrganizationId>,
        as_admin: bool,
    ) -> Result<(), CipherError> {
        let configs = self.get_api_configurations().await;
        let api = configs.api_client.ciphers_api();
        if as_admin {
            api.put_delete_many_admin(Some(CipherBulkDeleteRequestModel {
                ids: cipher_ids.into_iter().map(|id| id.to_string()).collect(),
                organization_id: organization_id.map(|id| id.to_string()),
            }))
            .await
            .unwrap(); // TODO: Map errors properly.
        } else {
            api.put_delete_many(Some(CipherBulkDeleteRequestModel {
                ids: cipher_ids.into_iter().map(|id| id.to_string()).collect(),
                organization_id: organization_id.map(|id| id.to_string()),
            }))
            .await
            .unwrap(); // TODO: Map errors properly.
        };
        Ok(())
    }
}
