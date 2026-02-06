use bitwarden_api_api::{
    apis::ciphers_api::CiphersApi,
    models::{CipherBulkShareRequestModel, CipherShareRequestModel},
};
use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{MissingFieldError, OrganizationId, require};
use bitwarden_crypto::EncString;
use bitwarden_state::repository::Repository;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    Cipher, CipherError, CipherId, CipherRepromptType, CipherView, CiphersClient,
    EncryptionContext, VaultParseError,
};

/// Standalone function that shares a cipher to an organization via API call.
/// This function is extracted to allow for easier testing with mocked dependencies.
async fn share_cipher(
    api_client: &dyn CiphersApi,
    repository: &dyn Repository<Cipher>,
    encrypted_cipher: EncryptionContext,
    collection_ids: Vec<CollectionId>,
) -> Result<Cipher, CipherError> {
    let cipher_id = require!(encrypted_cipher.cipher.id);
    let cipher_uuid: uuid::Uuid = cipher_id.into();

    let req = CipherShareRequestModel::new(
        collection_ids
            .iter()
            .map(<CollectionId as ToString>::to_string)
            .collect(),
        encrypted_cipher.into(),
    );

    let response = api_client.put_share(cipher_uuid, Some(req)).await?;

    let mut new_cipher: Cipher = response.try_into()?;
    new_cipher.collection_ids = collection_ids;

    repository.set(cipher_id, new_cipher.clone()).await?;

    Ok(new_cipher)
}

/// Standalone function that shares multiple ciphers to an organization via API call.
/// This function is extracted to allow for easier testing with mocked dependencies.
async fn share_ciphers_bulk(
    api_client: &dyn CiphersApi,
    repository: &dyn Repository<Cipher>,
    encrypted_ciphers: Vec<EncryptionContext>,
    collection_ids: Vec<CollectionId>,
) -> Result<Vec<Cipher>, CipherError> {
    let request = CipherBulkShareRequestModel::new(
        collection_ids
            .iter()
            .map(<CollectionId as ToString>::to_string)
            .collect(),
        encrypted_ciphers
            .into_iter()
            .map(|ec| ec.try_into())
            .collect::<Result<Vec<_>, _>>()?,
    );

    let response = api_client.put_share_many(Some(request)).await?;

    let cipher_minis = response.data.unwrap_or_default();
    let mut results = Vec::new();

    for cipher_mini in cipher_minis {
        // The server does not return the full Cipher object, so we pull the details from the
        // current local version to fill in those missing values.
        let orig_cipher = repository
            .get(CipherId::new(
                cipher_mini.id.ok_or(MissingFieldError("id"))?,
            ))
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
            archived_date: orig_cipher
                .as_ref()
                .map(|c| c.archived_date)
                .unwrap_or_default(),
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
            collection_ids: collection_ids.clone(),
            data: None,
        };

        repository.set(require!(cipher.id), cipher.clone()).await?;
        results.push(cipher)
    }

    Ok(results)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    fn update_organization_and_collections(
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

    /// Moves a cipher into an organization, adds it to collections, and calls the share_cipher API.
    pub async fn share_cipher(
        &self,
        mut cipher_view: CipherView,
        organization_id: OrganizationId,
        collection_ids: Vec<CollectionId>,
        original_cipher: Option<Cipher>,
    ) -> Result<Cipher, CipherError> {
        cipher_view = self.update_organization_and_collections(
            cipher_view,
            organization_id,
            collection_ids.clone(),
        )?;

        self.update_password_history(&mut cipher_view, original_cipher)
            .await?;

        let encrypted_cipher = self.encrypt(cipher_view)?;

        let api_client = &self
            .client
            .internal
            .get_api_configurations()
            .await
            .api_client;

        share_cipher(
            api_client.ciphers_api(),
            &*self.get_repository()?,
            encrypted_cipher,
            collection_ids,
        )
        .await
    }

    async fn update_password_history(
        &self,
        cipher_view: &mut CipherView,
        mut original_cipher: Option<Cipher>,
    ) -> Result<(), CipherError> {
        if let (Some(cipher_id), None) = (cipher_view.id, &original_cipher) {
            original_cipher = self.get_repository()?.get(cipher_id).await?;
        }
        if let Some(original_cipher_view) = original_cipher
            .map(|cipher| self.decrypt(cipher))
            .transpose()?
        {
            cipher_view.update_password_history(&original_cipher_view);
        }
        Ok(())
    }

    async fn prepare_encrypted_ciphers_for_bulk_share(
        &self,
        cipher_views: Vec<CipherView>,
        organization_id: OrganizationId,
        collection_ids: Vec<CollectionId>,
    ) -> Result<Vec<EncryptionContext>, CipherError> {
        let mut encrypted_ciphers: Vec<EncryptionContext> = Vec::new();
        for mut cv in cipher_views {
            cv = self.update_organization_and_collections(
                cv,
                organization_id,
                collection_ids.clone(),
            )?;
            self.update_password_history(&mut cv, None).await?;
            encrypted_ciphers.push(self.encrypt(cv)?);
        }
        Ok(encrypted_ciphers)
    }

    #[cfg(feature = "uniffi")]
    /// Prepares ciphers for bulk sharing by assigning them to an organization, adding them to
    /// collections, updating password history, and encrypting them. This method is exposed for
    /// UniFFI bindings. Can be removed once Mobile supports authenticated API calls via the SDK.
    pub async fn prepare_ciphers_for_bulk_share(
        &self,
        cipher_views: Vec<CipherView>,
        organization_id: OrganizationId,
        collection_ids: Vec<CollectionId>,
    ) -> Result<Vec<EncryptionContext>, CipherError> {
        self.prepare_encrypted_ciphers_for_bulk_share(cipher_views, organization_id, collection_ids)
            .await
    }

    /// Moves a group of ciphers into an organization, adds them to collections, and calls the
    /// share_ciphers API.
    pub async fn share_ciphers_bulk(
        &self,
        cipher_views: Vec<CipherView>,
        organization_id: OrganizationId,
        collection_ids: Vec<CollectionId>,
    ) -> Result<Vec<Cipher>, CipherError> {
        let encrypted_ciphers = self
            .prepare_encrypted_ciphers_for_bulk_share(
                cipher_views,
                organization_id,
                collection_ids.clone(),
            )
            .await?;

        let api_client = &self
            .client
            .internal
            .get_api_configurations()
            .await
            .api_client;

        share_ciphers_bulk(
            api_client.ciphers_api(),
            &*self.get_repository()?,
            encrypted_ciphers,
            collection_ids,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{CipherMiniResponseModelListResponseModel, CipherResponseModel},
    };
    use bitwarden_core::{
        Client,
        client::test_accounts::test_bitwarden_com_account,
        key_management::{
            MasterPasswordUnlockData, account_cryptographic_state::WrappedAccountCryptographicState,
        },
    };
    use bitwarden_test::{MemoryRepository, start_api_mock};
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;
    use crate::{CipherRepromptType, CipherType, LoginView, VaultClientExt};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
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
            attachment_decryption_failures: None,
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
            .update_organization_and_collections(
                cipher_view,
                organization_id,
                collection_ids.clone(),
            )
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

        let result = cipher_client.update_organization_and_collections(
            cipher_view,
            organization_id,
            collection_ids,
        );

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

        let result = cipher_client.update_organization_and_collections(
            cipher_view,
            organization_id,
            collection_ids,
        );

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

        // Register a repository with the client so get_repository() works
        let repository = MemoryRepository::<Cipher>::default();
        client
            .platform()
            .state()
            .register_client_managed(std::sync::Arc::new(repository));

        let cipher_client = client.vault().ciphers();

        // Create multiple ciphers with IDs, one already in org
        let cipher_view_1 = test_cipher_view_without_org();
        let mut cipher_view_2 = test_cipher_view_without_org();
        cipher_view_2.organization_id = Some(TEST_ORG_ID.parse().unwrap());

        // Encrypt and store cipher_view_1 in repository for password history lookup
        let encrypted_1 = cipher_client.encrypt(cipher_view_1.clone()).unwrap();
        let repository = cipher_client.get_repository().unwrap();
        repository
            .set(TEST_CIPHER_ID.parse().unwrap(), encrypted_1.cipher.clone())
            .await
            .unwrap();

        let organization_id: OrganizationId = TEST_ORG_ID.parse().unwrap();
        let collection_ids: Vec<CollectionId> = vec![TEST_COLLECTION_ID_1.parse().unwrap()];

        // Should fail because one cipher already has an organization
        let result = cipher_client
            .share_ciphers_bulk(
                vec![cipher_view_1, cipher_view_2],
                organization_id,
                collection_ids,
            )
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CipherError::OrganizationAlreadySet
        ));
    }

    fn create_encryption_context() -> EncryptionContext {
        use bitwarden_core::UserId;

        use crate::cipher::Login;

        // Create a minimal encrypted cipher for testing the API logic
        let cipher = Cipher {
                r#type: CipherType::Login,
                login: Some(Login {
                    username: Some("2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI=".parse().unwrap()),
                    password: Some("2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI=".parse().unwrap()),
                    password_revision_date: None,
                    uris: None,
                    totp: None,
                    autofill_on_page_load: None,
                    fido2_credentials: None,
                }),
                id: Some(TEST_CIPHER_ID.parse().unwrap()),
                organization_id: Some(TEST_ORG_ID.parse().unwrap()),
                folder_id: None,
                collection_ids: vec![TEST_COLLECTION_ID_1.parse().unwrap()],
                key: None,
                name: "2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI=".parse().unwrap(),
                notes: Some("2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI=".parse().unwrap()),
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
                data: None,
            };

        // Use a test user ID from the test accounts
        let user_id: UserId = "00000000-0000-0000-0000-000000000000".parse().unwrap();

        EncryptionContext {
            cipher,
            encrypted_for: user_id,
        }
    }

    #[tokio::test]
    async fn test_share_cipher_api_success() {
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let org_id: OrganizationId = TEST_ORG_ID.parse().unwrap();
        let collection_id: CollectionId = TEST_COLLECTION_ID_1.parse().unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api.expect_put_share().returning(move |_id, _body| {
                Ok(CipherResponseModel {
                    object: Some("cipher".to_string()),
                    id: Some(cipher_id.into()),
                    organization_id: Some(org_id.into()),
                    r#type: Some(bitwarden_api_api::models::CipherType::Login),
                    name: Some("2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI=".to_string()),
                    notes: Some("2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI=".to_string()),
                    login: Some(Box::new(bitwarden_api_api::models::CipherLoginModel {
                        username: Some("2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI=".to_string()),
                        password: Some("2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI=".to_string()),
                        ..Default::default()
                    })),
                    reprompt: Some(bitwarden_api_api::models::CipherRepromptType::None),
                    revision_date: Some("2024-01-30T17:55:36.150Z".to_string()),
                    creation_date: Some("2024-01-30T17:55:36.150Z".to_string()),
                    edit: Some(true),
                    view_password: Some(true),
                    organization_use_totp: Some(true),
                    favorite: Some(false),
                    ..Default::default()
                })
            });
        });

        let repository = MemoryRepository::<Cipher>::default();
        let encryption_context = create_encryption_context();
        let collection_ids: Vec<CollectionId> = vec![collection_id];

        let result = share_cipher(
            api_client.ciphers_api(),
            &repository,
            encryption_context,
            collection_ids.clone(),
        )
        .await;

        assert!(result.is_ok());
        let shared_cipher = result.unwrap();

        // Verify the cipher was stored in repository
        let stored_cipher = repository
            .get(TEST_CIPHER_ID.parse().unwrap())
            .await
            .unwrap()
            .expect("Cipher should be stored");

        assert_eq!(stored_cipher.id, shared_cipher.id);
        assert_eq!(
            stored_cipher
                .organization_id
                .as_ref()
                .map(ToString::to_string),
            Some(TEST_ORG_ID.to_string())
        );
        assert_eq!(stored_cipher.collection_ids, collection_ids);
    }

    #[tokio::test]
    async fn test_share_cipher_api_handles_404() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api.expect_put_share().returning(|_id, _body| {
                Err(bitwarden_api_api::apis::Error::Io(std::io::Error::other(
                    "Not found",
                )))
            });
        });

        let repository = MemoryRepository::<Cipher>::default();
        let encryption_context = create_encryption_context();
        let collection_ids: Vec<CollectionId> = vec![TEST_COLLECTION_ID_1.parse().unwrap()];

        let result = share_cipher(
            api_client.ciphers_api(),
            &repository,
            encryption_context,
            collection_ids,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_share_ciphers_bulk_api_success() {
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let org_id: OrganizationId = TEST_ORG_ID.parse().unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api.expect_put_share_many().returning(move |_body| {
                Ok(CipherMiniResponseModelListResponseModel {
                    object: Some("list".to_string()),
                    data: Some(vec![bitwarden_api_api::models::CipherMiniResponseModel {
                        object: Some("cipherMini".to_string()),
                        id: Some(cipher_id.into()),
                        organization_id: Some(org_id.into()),
                        r#type: Some(bitwarden_api_api::models::CipherType::Login),
                        name: Some("2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI=".to_string()),
                        revision_date: Some("2024-01-30T17:55:36.150Z".to_string()),
                        creation_date: Some("2024-01-30T17:55:36.150Z".to_string()),
                        ..Default::default()
                    }]),
                    continuation_token: None,
                })
            });
        });

        let repository = MemoryRepository::<Cipher>::default();

        // Pre-populate repository with original cipher data that will be used for missing fields
        let original_cipher = Cipher {
                r#type: CipherType::Login,
                login: Some(crate::cipher::Login {
                    username: Some("2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI=".parse().unwrap()),
                    password: Some("2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI=".parse().unwrap()),
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
                name: "2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI=".parse().unwrap(),
                notes: Some("2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI=".parse().unwrap()),
                identity: None,
                card: None,
                secure_note: None,
                ssh_key: None,
                favorite: true,
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
                data: None,
            };

        repository
            .set(TEST_CIPHER_ID.parse().unwrap(), original_cipher)
            .await
            .unwrap();

        let encryption_context = create_encryption_context();
        let collection_ids: Vec<CollectionId> = vec![
            TEST_COLLECTION_ID_1.parse().unwrap(),
            TEST_COLLECTION_ID_2.parse().unwrap(),
        ];

        let result = share_ciphers_bulk(
            api_client.ciphers_api(),
            &repository,
            vec![encryption_context],
            collection_ids.clone(),
        )
        .await;

        assert!(result.is_ok());
        let shared_ciphers = result.unwrap();
        assert_eq!(shared_ciphers.len(), 1);

        let shared_cipher = &shared_ciphers[0];
        assert_eq!(
            shared_cipher
                .organization_id
                .as_ref()
                .map(ToString::to_string),
            Some(TEST_ORG_ID.to_string())
        );
        assert_eq!(shared_cipher.collection_ids, collection_ids);

        // Verify the cipher was updated in repository
        let stored_cipher = repository
            .get(TEST_CIPHER_ID.parse().unwrap())
            .await
            .unwrap()
            .expect("Cipher should be stored");

        assert_eq!(stored_cipher.id, shared_cipher.id);
        assert!(stored_cipher.favorite); // Should preserve from original
    }

    #[tokio::test]
    async fn test_share_ciphers_bulk_api_handles_error() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api.expect_put_share_many().returning(|_body| {
                Err(bitwarden_api_api::apis::Error::Io(std::io::Error::other(
                    "Server error",
                )))
            });
        });

        let repository = MemoryRepository::<Cipher>::default();
        let encryption_context = create_encryption_context();
        let collection_ids: Vec<CollectionId> = vec![TEST_COLLECTION_ID_1.parse().unwrap()];

        let result = share_ciphers_bulk(
            api_client.ciphers_api(),
            &repository,
            vec![encryption_context],
            collection_ids,
        )
        .await;

        assert!(result.is_err());
    }

    async fn make_test_client_with_wiremock(mock_server: &wiremock::MockServer) -> Client {
        use bitwarden_core::{
            ClientSettings, DeviceType, UserId,
            key_management::crypto::{
                InitOrgCryptoRequest, InitUserCryptoMethod, InitUserCryptoRequest,
            },
        };
        use bitwarden_crypto::{EncString, Kdf};

        let settings = ClientSettings {
            identity_url: format!("http://{}", mock_server.address()),
            api_url: format!("http://{}", mock_server.address()),
            user_agent: "Bitwarden Test".into(),
            device_type: DeviceType::SDK,
            device_identifier: None,
            bitwarden_client_version: None,
            bitwarden_package_type: None,
        };

        let client = Client::new(Some(settings));

        client
            .internal
            .load_flags(std::collections::HashMap::from([(
                "enableCipherKeyEncryption".to_owned(),
                true,
            )]));

        let user_request = InitUserCryptoRequest {
            user_id: Some(UserId::new(uuid::uuid!("060000fb-0922-4dd3-b170-6e15cb5df8c8"))),
            kdf_params: Kdf::PBKDF2 {
                iterations: 600_000.try_into().unwrap(),
            },
            email: "test@bitwarden.com".to_owned(),
            account_cryptographic_state: WrappedAccountCryptographicState::V1 {
                private_key: "2.yN7l00BOlUE0Sb0M//Q53w==|EwKG/BduQRQ33Izqc/ogoBROIoI5dmgrxSo82sgzgAMIBt3A2FZ9vPRMY+GWT85JiqytDitGR3TqwnFUBhKUpRRAq4x7rA6A1arHrFp5Tp1p21O3SfjtvB3quiOKbqWk6ZaU1Np9HwqwAecddFcB0YyBEiRX3VwF2pgpAdiPbSMuvo2qIgyob0CUoC/h4Bz1be7Qa7B0Xw9/fMKkB1LpOm925lzqosyMQM62YpMGkjMsbZz0uPopu32fxzDWSPr+kekNNyLt9InGhTpxLmq1go/pXR2uw5dfpXc5yuta7DB0EGBwnQ8Vl5HPdDooqOTD9I1jE0mRyuBpWTTI3FRnu3JUh3rIyGBJhUmHqGZvw2CKdqHCIrQeQkkEYqOeJRJVdBjhv5KGJifqT3BFRwX/YFJIChAQpebNQKXe/0kPivWokHWwXlDB7S7mBZzhaAPidZvnuIhalE2qmTypDwHy22FyqV58T8MGGMchcASDi/QXI6kcdpJzPXSeU9o+NC68QDlOIrMVxKFeE7w7PvVmAaxEo0YwmuAzzKy9QpdlK0aab/xEi8V4iXj4hGepqAvHkXIQd+r3FNeiLfllkb61p6WTjr5urcmDQMR94/wYoilpG5OlybHdbhsYHvIzYoLrC7fzl630gcO6t4nM24vdB6Ymg9BVpEgKRAxSbE62Tqacxqnz9AcmgItb48NiR/He3n3ydGjPYuKk/ihZMgEwAEZvSlNxYONSbYrIGDtOY+8Nbt6KiH3l06wjZW8tcmFeVlWv+tWotnTY9IqlAfvNVTjtsobqtQnvsiDjdEVtNy/s2ci5TH+NdZluca2OVEr91Wayxh70kpM6ib4UGbfdmGgCo74gtKvKSJU0rTHakQ5L9JlaSDD5FamBRyI0qfL43Ad9qOUZ8DaffDCyuaVyuqk7cz9HwmEmvWU3VQ+5t06n/5kRDXttcw8w+3qClEEdGo1KeENcnXCB32dQe3tDTFpuAIMLqwXs6FhpawfZ5kPYvLPczGWaqftIs/RXJ/EltGc0ugw2dmTLpoQhCqrcKEBDoYVk0LDZKsnzitOGdi9mOWse7Se8798ib1UsHFUjGzISEt6upestxOeupSTOh0v4+AjXbDzRUyogHww3V+Bqg71bkcMxtB+WM+pn1XNbVTyl9NR040nhP7KEf6e9ruXAtmrBC2ah5cFEpLIot77VFZ9ilLuitSz+7T8n1yAh1IEG6xxXxninAZIzi2qGbH69O5RSpOJuJTv17zTLJQIIc781JwQ2TTwTGnx5wZLbffhCasowJKd2EVcyMJyhz6ru0PvXWJ4hUdkARJs3Xu8dus9a86N8Xk6aAPzBDqzYb1vyFIfBxP0oO8xFHgd30Cgmz8UrSE3qeWRrF8ftrI6xQnFjHBGWD/JWSvd6YMcQED0aVuQkuNW9ST/DzQThPzRfPUoiL10yAmV7Ytu4fR3x2sF0Yfi87YhHFuCMpV/DsqxmUizyiJuD938eRcH8hzR/VO53Qo3UIsqOLcyXtTv6THjSlTopQ+JOLOnHm1w8dzYbLN44OG44rRsbihMUQp+wUZ6bsI8rrOnm9WErzkbQFbrfAINdoCiNa6cimYIjvvnMTaFWNymqY1vZxGztQiMiHiHYwTfwHTXrb9j0uPM=|09J28iXv9oWzYtzK2LBT6Yht4IT4MijEkk0fwFdrVQ4=".parse::<EncString>().unwrap(),
            },
            method: InitUserCryptoMethod::MasterPasswordUnlock {
                password: "asdfasdfasdf".to_owned(),
                master_password_unlock: MasterPasswordUnlockData {
                    kdf: Kdf::PBKDF2 {
                        iterations: 600_000.try_into().unwrap(),
                    },
                    master_key_wrapped_user_key: "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=".parse().unwrap(),
                    salt: "test@bitwarden.com".to_owned(),
                },
            },
        };

        let org_request = InitOrgCryptoRequest {
            organization_keys: std::collections::HashMap::from([(
                TEST_ORG_ID.parse().unwrap(),
                "4.rY01mZFXHOsBAg5Fq4gyXuklWfm6mQASm42DJpx05a+e2mmp+P5W6r54WU2hlREX0uoTxyP91bKKwickSPdCQQ58J45LXHdr9t2uzOYyjVzpzebFcdMw1eElR9W2DW8wEk9+mvtWvKwu7yTebzND+46y1nRMoFydi5zPVLSlJEf81qZZ4Uh1UUMLwXz+NRWfixnGXgq2wRq1bH0n3mqDhayiG4LJKgGdDjWXC8W8MMXDYx24SIJrJu9KiNEMprJE+XVF9nQVNijNAjlWBqkDpsfaWTUfeVLRLctfAqW1blsmIv4RQ91PupYJZDNc8nO9ZTF3TEVM+2KHoxzDJrLs2Q==".parse().unwrap()
            )])
        };

        client
            .crypto()
            .initialize_user_crypto(user_request)
            .await
            .unwrap();
        client
            .crypto()
            .initialize_org_crypto(org_request)
            .await
            .unwrap();

        client
    }

    #[tokio::test]
    async fn test_share_cipher_with_password_history() {
        use bitwarden_test::start_api_mock;
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path_regex},
        };
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let org_id: OrganizationId = TEST_ORG_ID.parse().unwrap();
        let collection_id: CollectionId = TEST_COLLECTION_ID_1.parse().unwrap();

        let mut cipher_view = test_cipher_view_without_org();
        if let Some(ref mut login) = cipher_view.login {
            login.password = Some("original_password_123".to_string());
        }

        // Set up wiremock server with mock that echoes back the request data
        let mock = Mock::given(method("PUT"))
            .and(path_regex(r"/ciphers/[a-f0-9-]+/share"))
            .and(wiremock::matchers::body_string_contains("passwordHistory"))
            .respond_with(move |req: &wiremock::Request| {
                let body_bytes = req.body.as_slice();
                let request_body: bitwarden_api_api::models::CipherShareRequestModel =
                    serde_json::from_slice(body_bytes).expect("Failed to parse request body");

                // Echo back the cipher data
                let response = CipherResponseModel {
                    object: Some("cipher".to_string()),
                    id: Some(cipher_id.into()),
                    organization_id: Some(
                        request_body
                            .cipher
                            .organization_id
                            .unwrap()
                            .parse()
                            .unwrap(),
                    ),
                    r#type: request_body.cipher.r#type,
                    name: Some(request_body.cipher.name),
                    notes: request_body.cipher.notes,
                    login: request_body.cipher.login,
                    reprompt: request_body.cipher.reprompt,
                    password_history: request_body.cipher.password_history,
                    revision_date: Some("2024-01-30T17:55:36.150Z".to_string()),
                    creation_date: Some("2024-01-30T17:55:36.150Z".to_string()),
                    edit: Some(true),
                    view_password: Some(true),
                    organization_use_totp: Some(true),
                    favorite: request_body.cipher.favorite,
                    fields: request_body.cipher.fields,
                    key: request_body.cipher.key,
                    ..Default::default()
                };

                ResponseTemplate::new(200).set_body_json(&response)
            });

        // Set up the client with mocked server and repository.
        let (mock_server, _config) = start_api_mock(vec![mock]).await;
        let client = make_test_client_with_wiremock(&mock_server).await;
        let repository = std::sync::Arc::new(MemoryRepository::<Cipher>::default());
        let cipher_client = client.vault().ciphers();
        let encrypted_original = cipher_client.encrypt(cipher_view.clone()).unwrap();
        repository
            .set(
                TEST_CIPHER_ID.parse().unwrap(),
                encrypted_original.cipher.clone(),
            )
            .await
            .unwrap();

        client
            .platform()
            .state()
            .register_client_managed(repository.clone());

        // Change the password to make sure password_history is updated.
        if let Some(ref mut login) = cipher_view.login {
            login.password = Some("new_password_456".to_string());
        }

        let result = cipher_client
            .share_cipher(
                cipher_view.clone(),
                org_id,
                vec![collection_id],
                Some(encrypted_original.cipher),
            )
            .await;

        let shared_cipher = result.unwrap();
        assert_eq!(shared_cipher.organization_id, Some(org_id));
        let decrypted_view = cipher_client.decrypt(shared_cipher.clone()).unwrap();
        let history = decrypted_view.password_history.unwrap();
        assert_eq!(
            history.len(),
            1,
            "Password history should have 1 entry for the changed password"
        );
        assert_eq!(
            history[0].password, "original_password_123",
            "Password history should contain the original password"
        );
        assert_eq!(
            decrypted_view.login.as_ref().unwrap().password,
            Some("new_password_456".to_string()),
            "New password should be set"
        );
    }

    #[tokio::test]
    async fn test_share_ciphers_bulk_with_password_history() {
        let org_id: OrganizationId = TEST_ORG_ID.parse().unwrap();
        let collection_id: CollectionId = TEST_COLLECTION_ID_1.parse().unwrap();

        let mut cipher_view1 = test_cipher_view_without_org();
        cipher_view1.id = Some(TEST_CIPHER_ID.parse().unwrap());
        if let Some(ref mut login) = cipher_view1.login {
            login.password = Some("original_password_1".to_string());
        }

        let mut cipher_view2 = test_cipher_view_without_org();
        cipher_view2.id = Some("11111111-2222-3333-4444-555555555555".parse().unwrap());
        if let Some(ref mut login) = cipher_view2.login {
            login.password = Some("original_password_2".to_string());
        }

        // Set up wiremock server with mock that echoes back the request data
        let mock = Mock::given(method("PUT"))
            .and(path("/ciphers/share"))
            .and(wiremock::matchers::body_string_contains("passwordHistory"))
            .respond_with(move |req: &wiremock::Request| {
                let body_bytes = req.body.as_slice();
                let request_body: bitwarden_api_api::models::CipherBulkShareRequestModel =
                    serde_json::from_slice(body_bytes).expect("Failed to parse request body");

                // Echo back the cipher data
                let ciphers: Vec<_> = request_body
                    .ciphers
                    .into_iter()
                    .map(
                        |cipher| bitwarden_api_api::models::CipherMiniResponseModel {
                            object: Some("cipherMini".to_string()),
                            id: Some(cipher.id),
                            organization_id: cipher.organization_id.and_then(|id| id.parse().ok()),
                            r#type: cipher.r#type,
                            name: Some(cipher.name),
                            notes: cipher.notes,
                            login: cipher.login,
                            reprompt: cipher.reprompt,
                            password_history: cipher.password_history,
                            revision_date: Some("2024-01-30T17:55:36.150Z".to_string()),
                            creation_date: Some("2024-01-30T17:55:36.150Z".to_string()),
                            organization_use_totp: Some(true),
                            fields: cipher.fields,
                            key: cipher.key,
                            ..Default::default()
                        },
                    )
                    .collect();

                let response =
                    bitwarden_api_api::models::CipherMiniResponseModelListResponseModel {
                        object: Some("list".to_string()),
                        data: Some(ciphers),
                        continuation_token: None,
                    };

                ResponseTemplate::new(200).set_body_json(&response)
            });

        // Set up the client with mocked server and repository.
        let (mock_server, _config) = start_api_mock(vec![mock]).await;
        let client = make_test_client_with_wiremock(&mock_server).await;
        let repository = std::sync::Arc::new(MemoryRepository::<Cipher>::default());
        let cipher_client = client.vault().ciphers();

        let encrypted_original1 = cipher_client.encrypt(cipher_view1.clone()).unwrap();
        repository
            .set(
                encrypted_original1.cipher.id.unwrap(),
                encrypted_original1.cipher.clone(),
            )
            .await
            .unwrap();

        let encrypted_original2 = cipher_client.encrypt(cipher_view2.clone()).unwrap();
        repository
            .set(
                encrypted_original2.cipher.id.unwrap(),
                encrypted_original2.cipher.clone(),
            )
            .await
            .unwrap();

        client
            .platform()
            .state()
            .register_client_managed(repository.clone());

        // Change the passwords to make sure password_history is updated.
        if let Some(ref mut login) = cipher_view1.login {
            login.password = Some("new_password_1".to_string());
        }
        if let Some(ref mut login) = cipher_view2.login {
            login.password = Some("new_password_2".to_string());
        }

        let result = cipher_client
            .share_ciphers_bulk(
                vec![cipher_view1, cipher_view2],
                org_id,
                vec![collection_id],
            )
            .await;

        let shared_ciphers = result.unwrap();
        assert_eq!(shared_ciphers.len(), 2);

        let decrypted_view1 = cipher_client.decrypt(shared_ciphers[0].clone()).unwrap();
        assert_eq!(
            decrypted_view1.password_history.unwrap()[0].password,
            "original_password_1"
        );
        assert_eq!(
            decrypted_view1.login.unwrap().password,
            Some("new_password_1".to_string())
        );

        let decrypted_view2 = cipher_client.decrypt(shared_ciphers[1].clone()).unwrap();
        assert_eq!(
            decrypted_view2.password_history.unwrap()[0].password,
            "original_password_2"
        );
        assert_eq!(
            decrypted_view2.login.unwrap().password,
            Some("new_password_2".to_string())
        );
    }
}
