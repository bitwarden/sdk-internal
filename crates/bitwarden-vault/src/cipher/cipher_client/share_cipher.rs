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

#[cfg(test)]
mod tests {
    use bitwarden_core::{client::test_accounts::test_bitwarden_com_account, Client};

    use super::*;
    use crate::{CipherRepromptType, CipherType, LoginView, VaultClientExt};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    // Use the actual organization ID from test_bitwarden_com_account
    const TEST_ORG_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";
    const TEST_COLLECTION_ID_1: &str = "c1111111-1111-1111-1111-111111111111";
    const TEST_COLLECTION_ID_2: &str = "c2222222-2222-2222-2222-222222222222";

    fn test_cipher_view_without_org() -> CipherView {
        CipherView {
            r#type: CipherType::Login,
            login: Some(LoginView {
                username: Some("test@example.com".to_string()),
                password: Some("password123".to_string()),
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            id: Some(TEST_CIPHER_ID.parse().unwrap()),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: "My test login".to_string(),
            notes: Some("Test notes".to_string()),
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: true,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            fields: None,
            password_history: None,
            creation_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            archived_date: None,
        }
    }

    #[tokio::test]
    async fn test_move_to_collections_success() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let cipher_client = client.vault().ciphers();
        let cipher_view = test_cipher_view_without_org();
        let organization_id: OrganizationId = TEST_ORG_ID.parse().unwrap();
        let collection_ids: Vec<CollectionId> = vec![
            TEST_COLLECTION_ID_1.parse().unwrap(),
            TEST_COLLECTION_ID_2.parse().unwrap(),
        ];

        let result = cipher_client
            .move_to_collections(cipher_view, organization_id, collection_ids.clone())
            .unwrap();

        assert_eq!(result.organization_id, Some(organization_id));
        assert_eq!(result.collection_ids, collection_ids);
    }

    #[tokio::test]
    async fn test_move_to_collections_already_in_org() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let cipher_client = client.vault().ciphers();
        let mut cipher_view = test_cipher_view_without_org();
        cipher_view.organization_id = Some(TEST_ORG_ID.parse().unwrap());

        let organization_id: OrganizationId = TEST_ORG_ID.parse().unwrap();
        let collection_ids: Vec<CollectionId> = vec![TEST_COLLECTION_ID_1.parse().unwrap()];

        let result = cipher_client.move_to_collections(cipher_view, organization_id, collection_ids);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CipherError::OrganizationAlreadySet
        ));
    }

    #[tokio::test]
    async fn test_share_ciphers_bulk_already_in_org() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let cipher_client = client.vault().ciphers();
        let mut cipher_view = test_cipher_view_without_org();
        cipher_view.organization_id = Some(TEST_ORG_ID.parse().unwrap());

        let organization_id: OrganizationId = TEST_ORG_ID.parse().unwrap();
        let collection_ids: Vec<CollectionId> = vec![TEST_COLLECTION_ID_1.parse().unwrap()];

        let result = cipher_client
            .share_ciphers_bulk(vec![cipher_view], organization_id, collection_ids)
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CipherError::OrganizationAlreadySet
        ));
    }

    #[tokio::test]
    async fn test_move_to_collections_with_attachment_without_key_fails() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let cipher_client = client.vault().ciphers();
        let mut cipher_view = test_cipher_view_without_org();

        // Add an attachment WITHOUT a key - this should cause an error
        cipher_view.attachments = Some(vec![crate::AttachmentView {
            id: Some("attachment-456".to_string()),
            url: Some("https://example.com/attachment".to_string()),
            size: Some("2048".to_string()),
            size_name: Some("2 KB".to_string()),
            file_name: Some("test2.txt".to_string()),
            key: None, // No key!
            #[cfg(feature = "wasm")]
            decrypted_key: None,
        }]);

        let organization_id: OrganizationId = TEST_ORG_ID.parse().unwrap();
        let collection_ids: Vec<CollectionId> = vec![TEST_COLLECTION_ID_1.parse().unwrap()];

        let result =
            cipher_client.move_to_collections(cipher_view, organization_id, collection_ids);

        // Should fail because attachment is missing a key
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CipherError::AttachmentsWithoutKeys
        ));
    }

    #[tokio::test]
    async fn test_share_ciphers_bulk_multiple_validation() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let cipher_client = client.vault().ciphers();

        // Create multiple ciphers, one with organization already set
        let cipher_view_1 = test_cipher_view_without_org();
        let mut cipher_view_2 = test_cipher_view_without_org();
        cipher_view_2.organization_id = Some(TEST_ORG_ID.parse().unwrap());

        let organization_id: OrganizationId = TEST_ORG_ID.parse().unwrap();
        let collection_ids: Vec<CollectionId> = vec![TEST_COLLECTION_ID_1.parse().unwrap()];

        // Should fail because one cipher already has an organization
        let result = cipher_client
            .share_ciphers_bulk(vec![cipher_view_1, cipher_view_2], organization_id, collection_ids)
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CipherError::OrganizationAlreadySet
        ));
    }

    // Note: Full integration tests with API mocking for share_cipher and share_ciphers_bulk
    // would require the ability to inject a mocked ApiClient into the Client structure.
    // The current architecture retrieves the API client internally via
    // self.client.internal.get_api_client(), making it difficult to mock without
    // significant refactoring. These operations are tested end-to-end in integration tests
    // that run against actual API servers.
}
