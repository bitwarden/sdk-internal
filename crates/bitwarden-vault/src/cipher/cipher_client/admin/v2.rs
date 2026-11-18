//! [`CipherAdminClient`] operations that take and return the fully decrypted [`CipherViewV2`]
//! model.
//!
//! Each `_v2` method converts its input to the [`crate::CipherView`] model, runs the operation of
//! the same name without the suffix, and converts the result back.

use bitwarden_collections::collection::CollectionId;
use bitwarden_core::OrganizationId;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::{
    CipherAdminClient,
    create::CreateCipherAdminError,
    edit::EditCipherAdminError,
    get::{GetAssignedOrgCiphersAdminError, GetOrganizationCiphersAdminError, fetch_org_ciphers},
    restore::{RestoreCipherAdminError, restore_many_ciphers_as_admin},
};
use crate::{
    CipherCreateRequestV2, CipherEditRequestV2, CipherId, CipherListViewV2, CipherViewV2,
    DecryptCipherListResultV2, ListOrganizationCiphersResultV2,
    cipher::cipher_view_v2::{DecryptedCipher, view_to_v1, view_to_v2},
};

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CipherAdminClient {
    /// [`CipherAdminClient::create`] for the [`CipherViewV2`] model.
    pub async fn create_v2(
        &self,
        request: CipherCreateRequestV2,
    ) -> Result<CipherViewV2, CreateCipherAdminError> {
        let request = request.into_v1(&mut self.key_store.context())?;
        let view = self.create(request).await?;
        Ok(view_to_v2(&self.key_store, &view)?)
    }

    /// [`CipherAdminClient::edit`] for the [`CipherViewV2`] model.
    pub async fn edit_v2(
        &self,
        request: CipherEditRequestV2,
        original_cipher_view: CipherViewV2,
    ) -> Result<CipherViewV2, EditCipherAdminError> {
        let request = request.into_v1(&mut self.key_store.context())?;
        let original_cipher_view = view_to_v1(&self.key_store, &original_cipher_view)?;
        let view = self.edit(request, original_cipher_view).await?;
        Ok(view_to_v2(&self.key_store, &view)?)
    }

    /// [`CipherAdminClient::update_collection`] for the [`CipherViewV2`] model.
    pub async fn update_collection_v2(
        &self,
        cipher_id: CipherId,
        collection_ids: Vec<CollectionId>,
    ) -> Result<CipherViewV2, EditCipherAdminError> {
        let view = self.update_collection(cipher_id, collection_ids).await?;
        Ok(view_to_v2(&self.key_store, &view)?)
    }

    /// [`CipherAdminClient::restore`] for the [`CipherViewV2`] model.
    pub async fn restore_v2(
        &self,
        cipher_id: CipherId,
    ) -> Result<CipherViewV2, RestoreCipherAdminError> {
        let view = self.restore(cipher_id).await?;
        Ok(view_to_v2(&self.key_store, &view)?)
    }

    /// [`CipherAdminClient::restore_many`] for the [`CipherViewV2`] model.
    pub async fn restore_many_v2(
        &self,
        cipher_ids: Vec<CipherId>,
        org_id: OrganizationId,
    ) -> Result<DecryptCipherListResultV2, RestoreCipherAdminError> {
        let ciphers =
            restore_many_ciphers_as_admin(cipher_ids, org_id, &self.api_configurations.api_client)
                .await?;
        let (successes, failures) = CipherListViewV2::decrypt_ciphers_with_failures(
            &self.key_store,
            &ciphers,
            self.is_strict_decrypt().await,
        );
        Ok(DecryptCipherListResultV2 {
            successes,
            failures,
        })
    }

    /// [`CipherAdminClient::list_assigned_org_ciphers`] for the [`CipherViewV2`] model.
    pub async fn list_assigned_org_ciphers_v2(
        &self,
        org_id: OrganizationId,
    ) -> Result<ListOrganizationCiphersResultV2, GetAssignedOrgCiphersAdminError> {
        let ciphers = self.fetch_assigned_org_ciphers(org_id).await?;
        let (list_views, _failures) = CipherListViewV2::decrypt_ciphers_with_failures(
            &self.key_store,
            &ciphers,
            self.is_strict_decrypt().await,
        );
        Ok(ListOrganizationCiphersResultV2 {
            ciphers,
            list_views,
        })
    }

    /// [`CipherAdminClient::list_org_ciphers`] for the [`CipherViewV2`] model.
    pub async fn list_org_ciphers_v2(
        &self,
        org_id: OrganizationId,
        include_member_items: bool,
    ) -> Result<ListOrganizationCiphersResultV2, GetOrganizationCiphersAdminError> {
        let ciphers = fetch_org_ciphers(
            org_id,
            include_member_items,
            &self.api_configurations.api_client,
        )
        .await?;
        let (list_views, _failures) = CipherListViewV2::decrypt_ciphers_with_failures(
            &self.key_store,
            &ciphers,
            self.is_strict_decrypt().await,
        );
        Ok(ListOrganizationCiphersResultV2 {
            ciphers,
            list_views,
        })
    }
}
