use bitwarden_collections::collection::CollectionId;
use bitwarden_core::OrganizationId;
use bitwarden_vault::{
    Cipher, CipherCreateRequest, CipherEditRequest, CipherId, CipherListView,
    CipherPartialEditRequest, CipherView, DecryptCipherListResult, DecryptCipherResult,
    EncryptionContext, FolderId,
};

use crate::Result;

#[allow(missing_docs)]
#[derive(uniffi::Object)]
pub struct CiphersClient(pub(crate) bitwarden_vault::CiphersClient);

#[uniffi::export(async_runtime = "tokio")]
impl CiphersClient {
    /// Encrypt cipher
    pub async fn encrypt(&self, cipher_view: CipherView) -> Result<EncryptionContext> {
        Ok(self.0.encrypt(cipher_view).await?)
    }

    /// Decrypt cipher
    pub async fn decrypt(&self, cipher: Cipher) -> Result<CipherView> {
        Ok(self.0.decrypt(cipher).await?)
    }

    /// Decrypt cipher list
    pub async fn decrypt_list(&self, ciphers: Vec<Cipher>) -> Result<Vec<CipherListView>> {
        Ok(self.0.decrypt_list(ciphers).await?)
    }

    /// Encrypt a list of cipher views. Fails if any cipher fails to encrypt.
    pub async fn encrypt_list(
        &self,
        cipher_views: Vec<CipherView>,
    ) -> Result<Vec<EncryptionContext>> {
        Ok(self.0.encrypt_list(cipher_views).await?)
    }

    /// Decrypt cipher list with failures
    /// Returns both successfully decrypted ciphers and any that failed to decrypt
    // Note that this function still needs to return a Result, as the parameter conversion can still
    // fail
    pub async fn decrypt_list_with_failures(
        &self,
        ciphers: Vec<Cipher>,
    ) -> Result<DecryptCipherListResult> {
        Ok(self.0.decrypt_list_with_failures(ciphers).await)
    }

    /// Move a cipher to an organization, reencrypting the cipher key if necessary
    pub fn move_to_organization(
        &self,
        cipher: CipherView,
        organization_id: OrganizationId,
    ) -> Result<CipherView> {
        Ok(self.0.move_to_organization(cipher, organization_id)?)
    }

    /// Prepare ciphers for bulk share to an organization
    pub async fn prepare_ciphers_for_bulk_share(
        &self,
        ciphers: Vec<CipherView>,
        organization_id: OrganizationId,
        collection_ids: Vec<CollectionId>,
    ) -> Result<Vec<EncryptionContext>> {
        Ok(self
            .0
            .prepare_ciphers_for_bulk_share(ciphers, organization_id, collection_ids)
            .await?)
    }

    /// Decrypt full cipher list
    /// Returns both successfully fully decrypted ciphers and any that failed to decrypt
    // Note that this function still needs to return a Result, as the parameter conversion can still
    // fail
    pub async fn decrypt_list_full_with_failures(
        &self,
        ciphers: Vec<Cipher>,
    ) -> Result<DecryptCipherResult> {
        Ok(self.0.decrypt_list_full_with_failures(ciphers).await)
    }

    /// Create a new cipher and save it to the server and local state
    pub async fn create(&self, request: CipherCreateRequest) -> Result<CipherView> {
        Ok(self.0.create(request).await?)
    }

    /// Edit an existing cipher and save it to the server and local state
    pub async fn edit(&self, request: CipherEditRequest) -> Result<CipherView> {
        Ok(self.0.edit(request).await?)
    }

    /// Edit a PAM-gated cipher whose secrets were revealed under an active lease.
    ///
    /// Pass the full view obtained from the lease-authorised read as `original_cipher_view`. The
    /// returned view is partial, since the server withholds secrets from a gated write-return.
    pub async fn edit_gated(
        &self,
        request: CipherEditRequest,
        original_cipher_view: CipherView,
    ) -> Result<CipherView> {
        Ok(self.0.edit_gated(request, original_cipher_view).await?)
    }

    /// Update only the folder and favorite status of a cipher, for users without edit permission
    pub async fn edit_partial(&self, request: CipherPartialEditRequest) -> Result<CipherView> {
        Ok(self.0.edit_partial(request).await?)
    }

    /// Update the collections a cipher belongs to
    pub async fn update_collection(
        &self,
        cipher_id: CipherId,
        collection_ids: Vec<CollectionId>,
    ) -> Result<CipherView> {
        Ok(self
            .0
            .update_collection(cipher_id, collection_ids, false)
            .await?)
    }

    /// Get a cipher from local state and decrypt it
    pub async fn get(&self, cipher_id: CipherId) -> Result<CipherView> {
        Ok(self.0.get(&cipher_id.to_string()).await?)
    }

    /// Get all ciphers from local state and decrypt them to list views, returning both successes
    /// and failures
    pub async fn list(&self) -> Result<DecryptCipherListResult> {
        Ok(self.0.list().await?)
    }

    /// Get all ciphers from local state and fully decrypt them, returning both successes and
    /// failures
    pub async fn get_all(&self) -> Result<DecryptCipherResult> {
        Ok(self.0.get_all().await?)
    }

    /// Permanently delete a cipher from the server and local state
    pub async fn delete(&self, cipher_id: CipherId) -> Result<()> {
        Ok(self.0.delete(cipher_id).await?)
    }

    /// Permanently delete multiple ciphers from the server and local state
    pub async fn delete_many(
        &self,
        cipher_ids: Vec<CipherId>,
        organization_id: Option<OrganizationId>,
    ) -> Result<()> {
        Ok(self.0.delete_many(cipher_ids, organization_id).await?)
    }

    /// Move a cipher to the trash
    pub async fn soft_delete(&self, cipher_id: CipherId) -> Result<()> {
        Ok(self.0.soft_delete(cipher_id).await?)
    }

    /// Move multiple ciphers to the trash
    pub async fn soft_delete_many(
        &self,
        cipher_ids: Vec<CipherId>,
        organization_id: Option<OrganizationId>,
    ) -> Result<()> {
        Ok(self.0.soft_delete_many(cipher_ids, organization_id).await?)
    }

    /// Restore a cipher from the trash
    pub async fn restore(&self, cipher_id: CipherId) -> Result<CipherView> {
        Ok(self.0.restore(cipher_id).await?)
    }

    /// Restore multiple ciphers from the trash
    pub async fn restore_many(&self, cipher_ids: Vec<CipherId>) -> Result<DecryptCipherListResult> {
        Ok(self.0.restore_many(cipher_ids).await?)
    }

    /// Share a cipher with an organization, re-encrypting it with the organization key
    pub async fn share_cipher(
        &self,
        cipher_view: CipherView,
        organization_id: OrganizationId,
        collection_ids: Vec<CollectionId>,
        original_cipher_view: Option<CipherView>,
    ) -> Result<CipherView> {
        Ok(self
            .0
            .share_cipher(
                cipher_view,
                organization_id,
                collection_ids,
                original_cipher_view,
            )
            .await?)
    }

    /// Share multiple ciphers with an organization, re-encrypting them with the organization key
    pub async fn share_ciphers_bulk(
        &self,
        cipher_views: Vec<CipherView>,
        organization_id: OrganizationId,
        collection_ids: Vec<CollectionId>,
    ) -> Result<Vec<CipherView>> {
        Ok(self
            .0
            .share_ciphers_bulk(cipher_views, organization_id, collection_ids)
            .await?)
    }

    /// Move multiple ciphers to a folder, or out of any folder when `folder_id` is `None`
    pub async fn move_many(
        &self,
        cipher_ids: Vec<CipherId>,
        folder_id: Option<FolderId>,
    ) -> Result<()> {
        Ok(self.0.move_many(cipher_ids, folder_id).await?)
    }

    /// Add or remove collections for multiple organization ciphers
    pub async fn bulk_update_collections(
        &self,
        organization_id: OrganizationId,
        cipher_ids: Vec<CipherId>,
        collection_ids: Vec<CollectionId>,
        remove_collections: bool,
    ) -> Result<()> {
        Ok(self
            .0
            .bulk_update_collections(
                organization_id,
                cipher_ids,
                collection_ids,
                remove_collections,
            )
            .await?)
    }
}
