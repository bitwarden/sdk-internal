use bitwarden_api_api::models::{CipherCreateRequestModel, CipherMiniResponseModel};
use bitwarden_collections::collection::{self, CollectionId};
use bitwarden_core::{NotAuthenticatedError, OrganizationId};
use bitwarden_crypto::{CompositeEncryptable, IdentifyKey};

use crate::{
    Cipher, CipherError, CiphersClient,
    cipher_client::{
        create::{CipherCreateRequest, CipherCreateRequestInternal},
        edit::{CipherEditRequest, EditCipherError},
    },
};

// TS Api Service
// SDK
// postCipherAdmin(request: CipherCreateRequest)
#[allow(missing_docs)] // TODO: remove 
impl CiphersClient {
    // TODO / QUESTION - do we want to make this a separate operation? Or just add it to the existing `create` detail?
    // ciphers_admin_post
    pub async fn admin_create(
        &self,
        request: CipherCreateRequest,
        collection_ids: Vec<CollectionId>,
    ) -> Result<Cipher, CipherError> {
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

        Ok(cipher)
    }

    // getCiphersOrganization(organizationId)
    // ciphers_organization_details_get
    pub async fn admin_get_org_details(
        &self,
        org_id: OrganizationId,
        includeMemberItems: bool,
    ) -> Result<Cipher, CipherError> {
        let _ = org_id;
        todo!()
    }
    // deleteCipherAdmin(id)
    // ciphers_id_admin_delete
    pub async fn admin_delete(&self, request: CipherCreateRequest) -> Result<Cipher, CipherError> {
        todo!()
    }
    // deleteManyCiphersAdmin(request)
    // ciphers_admin_delete
    pub async fn admin_delete_many(
        &self,
        request: CipherCreateRequest,
    ) -> Result<Cipher, CipherError> {
        todo!()
    }
    // putCipherCollectionsAdmin(id, request)
    // ciphers_id_collections_admin_put
    pub async fn admin_update_collection(
        &self,
        request: CipherCreateRequest,
    ) -> Result<Cipher, CipherError> {
        todo!()
    }
    // putDeleteCipherAdmin(id)
    // ciphers_id_delete_admin_put
    pub async fn admin_soft_delete(
        &self,
        request: CipherCreateRequest,
    ) -> Result<Cipher, CipherError> {
        todo!()
    }
    // putDeleteManyCiphersAdmin(request)
    // ciphers_delete_admin_put
    pub async fn admin_soft_delete_many(
        &self,
        request: CipherCreateRequest,
    ) -> Result<Cipher, CipherError> {
        todo!()
    }
    // putRestoreCipherAdmin(id)
    // ciphers_id_restore_admin_put
    pub async fn admin_restore(&self, request: CipherCreateRequest) -> Result<Cipher, CipherError> {
        todo!()
    }
    // putRestoreManyCiphersAdmin(request)
    // ciphers_restore_admin_put
    pub async fn admin_restore_many(
        &self,
        request: CipherCreateRequest,
    ) -> Result<Cipher, CipherError> {
        todo!()
    }
}
