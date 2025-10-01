use bitwarden_api_api::models::{cipher, CipherBulkShareRequestModel, CipherShareRequestModel};
use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{require, MissingFieldError, OrganizationId};
use bitwarden_crypto::EncString;
use chrono::ParseError;
use uuid::Uuid;

use crate::{
    AttachmentView, Cipher, CipherError, CipherId, CipherRepromptType, CipherView, CiphersClient,
    VaultParseError,
};

impl CiphersClient {
    fn try_update_cipher_collections(
        &self,
        mut cipher_view: CipherView,
        organization_id: &OrganizationId,
        collection_ids: Vec<CollectionId>,
    ) -> Result<CipherView, CipherError> {
        if self
            .client
            .internal
            .get_flags()
            .enable_cipher_key_encryption
        {
            if cipher_view.organization_id.is_some() {
                return Err(CipherError::OrganizationAlreadySet);
            }

            cipher_view = self.move_to_organization(cipher_view, *organization_id)?;
            cipher_view.collection_ids = collection_ids.clone();
        } else {
            if let Some(attachments) = cipher_view.attachments.as_mut() {
                for attachment in attachments {
                    if attachment.key.is_none() {
                        todo!("Share attachment with server. Blocked by PM-25820")
                    }
                }
            }
            cipher_view.organization_id = Some(*organization_id);
            cipher_view.collection_ids = collection_ids.clone();
        }
        Ok(cipher_view)
    }

    #[allow(missing_docs)]
    /// Share a cipher with an organization and collections.
    pub async fn share_cipher(
        &self,
        mut cipher_view: CipherView,
        organization_id: &OrganizationId,
        collection_ids: Vec<CollectionId>,
        _original_cipher: Option<&Cipher>,
    ) -> Result<Cipher, CipherError> {
        cipher_view = self.try_update_cipher_collections(
            cipher_view,
            organization_id,
            collection_ids.clone(),
        )?;

        let cipher_id = cipher_view
            .id
            .map(Into::<Uuid>::into)
            .ok_or(MissingFieldError("id"))?;

        let encrypted_cipher = self.encrypt(cipher_view)?;

        let req = CipherShareRequestModel::new(
            collection_ids
                .iter()
                .map(<CollectionId as ToString>::to_string)
                .collect(),
            encrypted_cipher.into(),
        );
        let api_client = &self
            .client
            .internal
            .get_api_configurations()
            .await
            .api_client;

        let response = api_client
            .ciphers_api()
            .put_share(cipher_id, Some(req))
            .await?;

        let new_cipher: Cipher = response.try_into()?;

        self.get_repository()?
            .set(cipher_id.to_string(), new_cipher.clone())
            .await?;

        Ok(new_cipher)
    }

    async fn share_cipher_attachment(
        &self,
        attachmentView: AttachmentView,
        cipherId: &CipherId,
        organizationId: &OrganizationId,
        collectionIds: Vec<CollectionId>,
    ) -> Result<(), CipherError> {
        let api_client = &self
            .client
            .internal
            .get_api_configurations()
            .await
            .api_client;
        let attachment = api_client.ciphers_api().get_attachment_data(id, attachment_id)
        unimplemented!()
    }

    #[allow(missing_docs)]
    pub async fn share_ciphers_bulk(
        &self,
        cipher_views: Vec<CipherView>,
        organization_id: &OrganizationId,
        collection_ids: Vec<CollectionId>,
    ) -> Result<Vec<Cipher>, CipherError> {
        let results = cipher_views
            .into_iter()
            .map(|cv| {
                self.try_update_cipher_collections(cv, organization_id, collection_ids.clone())
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|cv| self.encrypt(cv))
            .collect::<Result<Vec<_>, _>>()?;

        let request = CipherBulkShareRequestModel::new(
            collection_ids
                .iter()
                .map(<CollectionId as ToString>::to_string)
                .collect(),
            results.into_iter().map(Into::into).collect(),
        );
        let api_client = &self
            .client
            .internal
            .get_api_configurations()
            .await
            .api_client;

        let response = api_client
            .ciphers_api()
            .put_share_many(Some(request))
            .await?;

        let repo = self.get_repository()?;
        let mut results = Vec::new();
        for cipher_mini in require!(response.data).into_iter() {
            let Some(orig_cipher) = repo
                .get(cipher_mini.id.ok_or(MissingFieldError("id"))?.to_string())
                .await?
            else {
                continue; // TODO: handle missing original cipher
            };
            let cipher: Cipher = Cipher {
                id: cipher_mini.id.map(CipherId::new),
                organization_id: cipher_mini.organization_id.map(OrganizationId::new),
                folder_id: orig_cipher.folder_id,
                key: EncString::try_from_optional(cipher_mini.key)?,
                name: require!(EncString::try_from_optional(cipher_mini.name)?),
                notes: EncString::try_from_optional(cipher_mini.notes)?,
                r#type: require!(cipher_mini.r#type).into(),
                login: cipher_mini.login.map(|l| (*l).try_into()).transpose()?,
                identity: cipher_mini.identity.map(|i| (*i).try_into()).transpose()?,
                card: cipher_mini.card.map(|c| (*c).try_into()).transpose()?,
                secure_note: cipher_mini
                    .secure_note
                    .map(|s| (*s).try_into())
                    .transpose()?,
                ssh_key: cipher_mini.ssh_key.map(|s| (*s).try_into()).transpose()?,
                reprompt: cipher_mini
                    .reprompt
                    .map(|r| r.into())
                    .unwrap_or(CipherRepromptType::None),
                organization_use_totp: cipher_mini.organization_use_totp.unwrap_or(true),
                attachments: cipher_mini
                    .attachments
                    .map(|a| a.into_iter().map(|a| a.try_into()).collect())
                    .transpose()?,
                fields: cipher_mini
                    .fields
                    .map(|f| f.into_iter().map(|f| f.try_into()).collect())
                    .transpose()?,
                password_history: cipher_mini
                    .password_history
                    .map(|p| p.into_iter().map(|p| p.try_into()).collect())
                    .transpose()?,
                creation_date: require!(cipher_mini.creation_date)
                    .parse()
                    .map_err(Into::<VaultParseError>::into)?,
                deleted_date: cipher_mini
                    .deleted_date
                    .map(|d| d.parse())
                    .transpose()
                    .map_err(Into::<VaultParseError>::into)?,
                revision_date: require!(cipher_mini.revision_date)
                    .parse()
                    .map_err(Into::<VaultParseError>::into)?,
                archived_date: cipher_mini
                    .archived_date
                    .map(|d| d.parse())
                    .transpose()
                    .map_err(Into::<VaultParseError>::into)?,
                // TODO: Confirm this is the correct approach (yanking from existing cipher in repository)
                // Maybe update the server to return the full cipher - Slack thread:
                favorite: orig_cipher.favorite,
                edit: orig_cipher.edit,
                permissions: orig_cipher.permissions,
                view_password: orig_cipher.view_password,
                local_data: orig_cipher.local_data,
                collection_ids: collection_ids.clone(), // TODO: No confirmation from server that they were set?
            };
            self.get_repository()?
                .set(require!(cipher.id).to_string(), cipher.clone())
                .await?;
            results.push(cipher)
        }
        Ok(results)
    }

    async fn upsert(&self, cipher: Cipher) -> Result<(), CipherError> {
        self.get_repository()?
            .set(require!(cipher.id).to_string(), cipher.clone())
            .await?;
        Ok(())
    }

    #[allow(missing_docs)]
    pub async fn share_cipher_attachment(
        &self,
        _cipher: &Cipher,
        _attachment_id: &str,
        _organization_id: &OrganizationId,
        _collection_ids: Vec<CollectionId>,
    ) -> Result<(), CipherError> {
        unimplemented!()
    }
}
