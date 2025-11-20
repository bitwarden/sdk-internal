use bitwarden_api_api::models::{
    CipherBulkRestoreRequestModel, CipherCollectionsRequestModel, CipherCreateRequestModel,
    CipherMiniResponseModelListResponseModel,
};
use bitwarden_collections::collection::CollectionId;
use bitwarden_core::OrganizationId;
use bitwarden_crypto::{Decryptable, IdentifyKey};

use crate::{
    Cipher, CipherError, CipherId, CipherView, CiphersClient, DecryptCipherListResult,
    cipher_client::create::{CipherCreateRequest, CipherCreateRequestInternal},
};

#[allow(missing_docs)] // TODO: remove 
impl CiphersClient {
    // TODO Add it to the existing `create` detail - doesn't need a separate impl to just acll a different endpoint.
    // ciphers_admin_post
    pub async fn admin_create(
        &self,
        request: CipherCreateRequest,
        collection_ids: Vec<CollectionId>,
    ) -> Result<CipherView, CipherError> {
        // let api_req = request
        let mut request_internal: CipherCreateRequestInternal = request.into();
        let key_store = self.client.internal.get_key_store();

        // TODO: move this to CipherCreateRequestInternal::CompositeEncryptable implementation
        // once the feature flag is removed.
        if self
            .client
            .internal
            .get_flags()
            .enable_cipher_key_encryption
        {
            let key = request_internal.key_identifier();
            request_internal
                .generate_cipher_key(&mut self.client.internal.get_key_store().context(), key)?;
        }

        let request = CipherCreateRequestModel {
            collection_ids: Some(collection_ids.clone().into_iter().map(Into::into).collect()),
            cipher: Box::new(key_store.encrypt(request_internal)?),
        };

        let response = self
            .client
            .internal
            .get_api_configurations()
            .await
            .api_client
            .ciphers_api()
            .post_admin(Some(request))
            .await;

        let mut cipher: Cipher = response.unwrap().try_into()?; // TODO: Fix unwrap
        cipher.collection_ids = collection_ids;

        Ok(self.decrypt(cipher)?)
    }

    // ciphers_id_collections_admin_put
    pub async fn update_collection(
        &self,
        cipher_id: CipherId,
        collection_ids: Vec<CollectionId>,
        is_admin: bool,
    ) -> Result<CipherView, CipherError> {
        let req = CipherCollectionsRequestModel {
            collection_ids: collection_ids
                .into_iter()
                .map(|id| id.to_string())
                .collect(),
        };

        let api_config = self.get_api_configurations().await;
        let api = api_config.api_client.ciphers_api();
        let cipher = if is_admin {
            api.put_collections_admin(&cipher_id.to_string(), Some(req))
                .await
                .unwrap()
                .try_into()?
        } else {
            let response: Cipher = api
                .put_collections(cipher_id.into(), Some(req))
                .await
                .unwrap()
                .try_into()?; // TODO: the uszhe
            self.get_repository()?
                .set(cipher_id.to_string(), response.clone())
                .await?;
            response
        };

        Ok(self.decrypt(cipher)?)
    }

    pub async fn restore(
        &self,
        cipher_id: CipherId,
        is_admin: bool,
    ) -> Result<CipherView, CipherError> {
        let api_config = self.get_api_configurations().await;
        let api = api_config.api_client.ciphers_api();

        let cipher: Cipher = if is_admin {
            let response = api.put_restore_admin(cipher_id.into()).await.unwrap();
            response.try_into()?
        } else {
            let response = api.put_restore(cipher_id.into()).await.unwrap();
            let cipher: Cipher = response.try_into()?;

            cipher
        };

        Ok(self.decrypt(cipher)?)
    }

    pub async fn admin_restore_many(
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
            .await
            .unwrap() // TODO - handle error
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
            .await
            .unwrap() // TODO - handle error
            .data
            .into_iter()
            .flatten()
            .map(|c| c.try_into())
            .collect::<Result<Vec<Cipher>, _>>()?
        };
        Ok(self.decrypt_list_with_failures(ciphers))
    }
}
