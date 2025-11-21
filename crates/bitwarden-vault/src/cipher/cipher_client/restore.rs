use bitwarden_api_api::models::CipherBulkRestoreRequestModel;
use bitwarden_core::OrganizationId;

use crate::{Cipher, CipherError, CipherId, CipherView, CiphersClient, DecryptCipherListResult};

impl CiphersClient {
    pub async fn restore(
        &self,
        cipher_id: CipherId,
        is_admin: bool,
    ) -> Result<CipherView, CipherError> {
        let api_config = self.get_api_configurations().await;
        let api = api_config.api_client.ciphers_api();

        let cipher: Cipher = if is_admin {
            let response = api.put_restore_admin(cipher_id.into()).await?;
            response.try_into()?
        } else {
            let response = api.put_restore(cipher_id.into()).await?;
            let cipher: Cipher = response.try_into()?;

            cipher
        };

        Ok(self.decrypt(cipher)?)
    }

    pub async fn restore_many(
        &self,
        cipher_ids: Vec<CipherId>,
        org_id: Option<OrganizationId>,
    ) -> Result<DecryptCipherListResult, CipherError> {
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
