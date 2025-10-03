use bitwarden_api_api::models::{
    CipherBulkShareRequestModel, CipherMiniResponseModel, CipherShareRequestModel,
};
use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{require, MissingFieldError, OrganizationId};
use bitwarden_crypto::EncString;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    Cipher, CipherError, CipherId, CipherRepromptType, CipherView, CiphersClient, VaultParseError,
};

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    fn move_to_collections(
        &self,
        mut cipher_view: CipherView,
        organization_id: OrganizationId,
        collection_ids: Vec<CollectionId>,
    ) -> Result<CipherView, CipherError> {
        let organization_id = &organization_id;
        if cipher_view.organization_id.is_some() {
            return Err(CipherError::OrganizationAlreadySet);
        }

        cipher_view = self.move_to_organization(cipher_view, *organization_id)?;
        cipher_view.collection_ids = collection_ids;
        Ok(cipher_view)
    }

    /// Moves a cipher into an organization and collections.
    pub async fn share_cipher(
        &self,
        mut cipher_view: CipherView,
        organization_id: OrganizationId,
        collection_ids: Vec<CollectionId>,
        _original_cipher: Option<Cipher>,
    ) -> Result<Cipher, CipherError> {
        cipher_view =
            self.move_to_collections(cipher_view, organization_id, collection_ids.clone())?;

        let cipher_id = require!(cipher_view.id).into();
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

    #[allow(missing_docs)]
    pub async fn share_ciphers_bulk(
        &self,
        cipher_views: Vec<CipherView>,
        organization_id: OrganizationId,
        collection_ids: Vec<CollectionId>,
    ) -> Result<Vec<Cipher>, CipherError> {
        let encrypted_ciphers = cipher_views
            .into_iter()
            .map(|cv| self.move_to_collections(cv, organization_id, collection_ids.clone()))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|cv| self.encrypt(cv))
            .collect::<Result<Vec<_>, _>>()?;

        let request = CipherBulkShareRequestModel::new(
            collection_ids
                .iter()
                .map(<CollectionId as ToString>::to_string)
                .collect(),
            encrypted_ciphers
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
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
        let results = self
            .update_repository_from_bulk_share_response(
                response.data.unwrap_or_default(),
                collection_ids,
            )
            .await?;
        Ok(results)
    }

    async fn update_repository_from_bulk_share_response(
        &self,
        ciphers: Vec<CipherMiniResponseModel>,
        collection_ids: Vec<CollectionId>,
    ) -> Result<Vec<Cipher>, CipherError> {
        let repo = self.get_repository()?;
        let mut results = Vec::new();
        for cipher_mini in ciphers {
            // The server does not return the full Cipher object, so we pull the details from the
            // current local version to fill in those missing values.
            let orig_cipher = repo
                .get(cipher_mini.id.ok_or(MissingFieldError("id"))?.to_string())
                .await?;

            let cipher: Cipher = Cipher {
                id: cipher_mini.id.map(CipherId::new),
                organization_id: cipher_mini.organization_id.map(OrganizationId::new),
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
                edit: orig_cipher.as_ref().map(|c| c.edit).unwrap_or_default(),
                favorite: orig_cipher.as_ref().map(|c| c.favorite).unwrap_or_default(),
                folder_id: orig_cipher
                    .as_ref()
                    .map(|c| c.folder_id)
                    .unwrap_or_default(),
                permissions: orig_cipher
                    .as_ref()
                    .map(|c| c.permissions)
                    .unwrap_or_default(),
                view_password: orig_cipher
                    .as_ref()
                    .map(|c| c.view_password)
                    .unwrap_or_default(),
                local_data: orig_cipher.map(|c| c.local_data).unwrap_or_default(),
                collection_ids: collection_ids.clone(), /* Should we have confirmation from the
                                                         * server that these were set?? */
            };
            repo.set(require!(cipher.id).to_string(), cipher.clone())
                .await?;
            results.push(cipher)
        }
        Ok(results)
    }
}
