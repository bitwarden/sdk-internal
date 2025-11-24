use bitwarden_api_api::models::{CipherBulkDeleteRequestModel, CipherBulkRestoreRequestModel};
use bitwarden_core::{ApiError, OrganizationId};
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::{
    Cipher, CipherId, CipherView, CiphersClient, DecryptCipherListResult, DecryptError,
    VaultParseError,
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum RestoreCipherError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    #[error(transparent)]
    Decrypt(#[from] DecryptError),
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for RestoreCipherError {
    fn from(val: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(val.into())
    }
}

impl CiphersClient {
    /// Deletes the [Cipher] with the matching [CipherId] from the server, using the admin endpoint.
    pub async fn delete_as_admin(&self, cipher_id: CipherId) -> Result<(), ApiError> {
        let configs = self.get_api_configurations().await;
        let api = configs.api_client.ciphers_api();
        api.delete_admin(cipher_id.into()).await?;
        Ok(())
    }

    /// Deletes the [Cipher] with the matching [CipherId] from the server.
    pub async fn delete(&self, cipher_id: CipherId) -> Result<(), ApiError> {
        let configs = self.get_api_configurations().await;
        let api = configs.api_client.ciphers_api();
        api.delete(cipher_id.into()).await?;
        Ok(())
    }

    /// Deletes all [Cipher] objects with a matching [CipherId] from the server, using the admin endpoint.
    pub async fn delete_many_as_admin(
        &self,
        cipher_ids: Vec<CipherId>,
        organization_id: Option<OrganizationId>,
    ) -> Result<(), ApiError> {
        let configs = self.get_api_configurations().await;
        let api = configs.api_client.ciphers_api();
        api.delete_many_admin(Some(CipherBulkDeleteRequestModel {
            ids: cipher_ids.into_iter().map(|id| id.to_string()).collect(),
            organization_id: organization_id.map(|id| id.to_string()),
        }))
        .await?;
        Ok(())
    }

    /// Deletes all [Cipher] objects with a matching [CipherId] from the server.
    pub async fn delete_many(
        &self,
        cipher_ids: Vec<CipherId>,
        organization_id: Option<OrganizationId>,
    ) -> Result<(), ApiError> {
        let configs = self.get_api_configurations().await;
        let api = configs.api_client.ciphers_api();
        api.delete_many(Some(CipherBulkDeleteRequestModel {
            ids: cipher_ids.into_iter().map(|id| id.to_string()).collect(),
            organization_id: organization_id.map(|id| id.to_string()),
        }))
        .await?;
        Ok(())
    }

    /// Soft-deletes the [Cipher] with the matching [CipherId] from the server.
    pub async fn soft_delete(&self, cipher_id: CipherId) -> Result<(), ApiError> {
        let configs = self.get_api_configurations().await;
        let api = configs.api_client.ciphers_api();
        api.put_delete(cipher_id.into()).await?;
        Ok(())
    }

    /// Soft-deletes the [Cipher] with the matching [CipherId] from the server, using the admin endpoint.
    pub async fn soft_delete_as_admin(&self, cipher_id: CipherId) -> Result<(), ApiError> {
        let configs = self.get_api_configurations().await;
        let api = configs.api_client.ciphers_api();
        api.put_delete_admin(cipher_id.into()).await?; // TODO: Map errors properly.
        Ok(())
    }

    /// Soft-deletes all [Cipher] objects for the given [CipherId]s from the server.
    pub async fn soft_delete_many(
        &self,
        cipher_ids: Vec<CipherId>,
        organization_id: Option<OrganizationId>,
    ) -> Result<(), ApiError> {
        let configs = self.get_api_configurations().await;
        let api = configs.api_client.ciphers_api();
        api.put_delete_many(Some(CipherBulkDeleteRequestModel {
            ids: cipher_ids.into_iter().map(|id| id.to_string()).collect(),
            organization_id: organization_id.map(|id| id.to_string()),
        }))
        .await?;
        Ok(())
    }

    /// Soft-deletes all [Cipher] objects for the given [CipherId]s from the server, using the admin endpoint.
    pub async fn soft_delete_many_as_admin(
        &self,
        cipher_ids: Vec<CipherId>,
        organization_id: Option<OrganizationId>,
    ) -> Result<(), ApiError> {
        let configs = self.get_api_configurations().await;
        let api = configs.api_client.ciphers_api();
        api.put_delete_many_admin(Some(CipherBulkDeleteRequestModel {
            ids: cipher_ids.into_iter().map(|id| id.to_string()).collect(),
            organization_id: organization_id.map(|id| id.to_string()),
        }))
        .await?;
        Ok(())
    }

    /// Restores a soft-deleted cipher on the server.
    pub async fn restore(&self, cipher_id: CipherId) -> Result<CipherView, RestoreCipherError> {
        let api_config = self.get_api_configurations().await;
        let api = api_config.api_client.ciphers_api();

        let cipher: Cipher = api.put_restore(cipher_id.into()).await?.try_into()?;

        Ok(self.decrypt(cipher)?)
    }

    /// Restores a soft-deleted cipher on the server, using the admin endpoint.
    pub async fn restore_as_admin(
        &self,
        cipher_id: CipherId,
    ) -> Result<CipherView, RestoreCipherError> {
        let api_config = self.get_api_configurations().await;
        let api = api_config.api_client.ciphers_api();

        let cipher: Cipher = api.put_restore_admin(cipher_id.into()).await?.try_into()?;

        Ok(self.decrypt(cipher)?)
    }

    /// Restores multiple soft-deleted ciphers on the server.
    pub async fn restore_many(
        &self,
        cipher_ids: Vec<CipherId>,
        org_id: Option<OrganizationId>,
    ) -> Result<DecryptCipherListResult, RestoreCipherError> {
        let api_config = self.get_api_configurations().await;
        let api = api_config.api_client.ciphers_api();

        let ciphers: Vec<Cipher> = if let Some(org_id) = org_id {
            api.put_restore_many_admin(Some(CipherBulkRestoreRequestModel {
                ids: cipher_ids.into_iter().map(|id| id.to_string()).collect(),
                organization_id: Some(org_id.into()),
            }))
            .await?
            .data
            .into_iter()
            .flatten()
            .map(|c| c.try_into())
            .collect::<Result<Vec<_>, _>>()?
        } else {
            api.put_restore_many(Some(CipherBulkRestoreRequestModel {
                ids: cipher_ids.into_iter().map(|id| id.to_string()).collect(),
                organization_id: None,
            }))
            .await?
            .data
            .into_iter()
            .flatten()
            .map(|c| c.try_into())
            .collect::<Result<Vec<Cipher>, _>>()?
        };
        Ok(self.decrypt_list_with_failures(ciphers))
    }
}
