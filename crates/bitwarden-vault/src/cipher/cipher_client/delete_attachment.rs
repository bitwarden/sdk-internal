use bitwarden_api_api::{apis::ciphers_api::CiphersApi, models};
use bitwarden_core::require;
use bitwarden_state::repository::Repository;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{Cipher, CipherError, CipherId, CiphersClient, VaultParseError};

/// Standalone function to delete an attachment from a cipher that is extracted for ease of unit
/// testing.
async fn delete_attachment(
    api_client: &dyn CiphersApi,
    repository: &dyn Repository<Cipher>,
    cipher_id: CipherId,
    attachment_id: &str,
    admin: bool,
) -> Result<Cipher, CipherError> {
    let response = if admin {
        api_client
            .delete_attachment_admin(cipher_id.into(), attachment_id)
            .await?
    } else {
        api_client
            .delete_attachment(cipher_id.into(), attachment_id)
            .await?
    };

    let cipher_response: Box<models::Cipher> = require!(response.cipher);
    let mut cipher = require!(repository.get(cipher_id.to_string()).await?);

    cipher.revision_date = require!(cipher_response.revision_date)
        .parse()
        .map_err(Into::<VaultParseError>::into)?;

    if let Some(ref mut attachments) = cipher.attachments {
        attachments.retain(|a| a.id.as_deref() != Some(attachment_id));
    }

    repository
        .set(cipher_id.to_string(), cipher.clone())
        .await?;

    Ok(cipher)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    /// Delete an attachment from a cipher
    pub async fn delete_attachment(
        &self,
        cipher_id: CipherId,
        attachment_id: &str,
    ) -> Result<Cipher, CipherError> {
        let config = self.client.internal.get_api_configurations().await;

        delete_attachment(
            config.api_client.ciphers_api(),
            &*self.get_repository()?,
            cipher_id,
            &attachment_id,
            false,
        )
        .await
    }

    /// Delete an attachment from a cipher as an administrator
    pub async fn delete_attachment_as_admin(
        &self,
        cipher_id: CipherId,
        attachment_id: &str,
    ) -> Result<Cipher, CipherError> {
        let config = self.client.internal.get_api_configurations().await;

        delete_attachment(
            config.api_client.ciphers_api(),
            &*self.get_repository()?,
            cipher_id,
            &attachment_id,
            true,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models};
    use bitwarden_test::MemoryRepository;

    use super::*;
    use crate::{Attachment, CipherRepromptType, CipherType};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_ATTACHMENT_ID_TO_DELETE: &str = "attachment-to-delete";
    const TEST_ATTACHMENT_ID_TO_KEEP: &str = "attachment-to-keep";

    fn test_attachment_to_delete() -> Attachment {
        Attachment {
            id: Some(TEST_ATTACHMENT_ID_TO_DELETE.to_string()),
            url: Some("http://localhost:4000/attachments/path1".to_string()),
            file_name: Some(
                "2.mV50WiLq6duhwGbhM1TO0A==|dTufWNH8YTPP0EMlNLIpFA==|QHp+7OM8xHtEmCfc9QPXJ0Ro2BeakzvLgxJZ7NdLuDc="
                    .parse()
                    .unwrap(),
            ),
            key: None,
            size: Some("65".to_string()),
            size_name: Some("65 Bytes".to_string()),
        }
    }

    fn test_attachment_to_keep() -> Attachment {
        Attachment {
            id: Some(TEST_ATTACHMENT_ID_TO_KEEP.to_string()),
            url: Some("http://localhost:4000/attachments/path2".to_string()),
            file_name: Some(
                "2.GhazFdCYQcM5v+AtVwceQA==|98bMUToqC61VdVsSuXWRwA==|bsLByMht9Hy5QO9pPMRz0K4d0aqBiYnnROGM5YGbNu4="
                    .parse()
                    .unwrap(),
            ),
            key: Some(
                "2.6TPEiYULFg/4+3CpDRwCqw==|6swweBHCJcd5CHdwBBWuRN33XRV22VoroDFDUmiM4OzjPEAhgZK57IZS1KkBlCcFvT+t+YbsmDcdv+Lqr+iJ3MmzfJ40MCB5TfYy+22HVRA=|UvmtuC96O+96TvemAC7SFj1xJkXwK3Su5AnGmXcwXH0="
                    .parse()
                    .unwrap(),
            ),
            size: Some("100".to_string()),
            size_name: Some("100 Bytes".to_string()),
        }
    }

    fn create_cipher_fixture(cipher_id: CipherId) -> Cipher {
        Cipher {
            id: Some(cipher_id),
            r#type: CipherType::Login,
            login: Some(crate::cipher::Login {
                username: Some(
                    "2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI="
                        .parse()
                        .unwrap(),
                ),
                password: Some(
                    "2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI="
                        .parse()
                        .unwrap(),
                ),
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            name: "2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI="
                .parse()
                .unwrap(),
            notes: Some("2.rSw0uVQEFgUCEmOQx0JnDg==|MKqHLD25aqaXYHeYJPH/mor7l3EeSQKsI7A/R+0bFTI=|ODcUScISzKaZWHlUe4MRGuTT2S7jpyDmbOHl7d+6HiM=".parse().unwrap()),
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: true,
            edit: true,
            view_password: true,
            local_data: None,
            attachments: Some(vec![test_attachment_to_delete(), test_attachment_to_keep()]),
            fields: None,
            password_history: None,
            creation_date: "2024-01-20T17:00:00.000Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-01-20T17:55:36.150Z".parse().unwrap(),
            archived_date: None,
            folder_id: None,
            organization_id: None,
            collection_ids: vec![],
            key: None,
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            permissions: None,
            data: None,
        }
    }

    fn mock_delete_attachment_success() -> ApiClient {
        ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_delete_attachment()
                .returning(move |_id, _attachment_id| {
                    Ok(models::DeleteAttachmentResponseData {
                        cipher: Some(Box::new(models::Cipher {
                            revision_date: Some("2024-01-30T18:00:00.000Z".to_string()),
                            ..Default::default()
                        })),
                    })
                });
        })
    }

    fn mock_delete_attachment_admin_success() -> ApiClient {
        ApiClient::new_mocked(move |mock| {
            mock.ciphers_api.expect_delete_attachment_admin().returning(
                move |_id, _attachment_id| {
                    Ok(models::DeleteAttachmentResponseData {
                        cipher: Some(Box::new(models::Cipher {
                            revision_date: Some("2024-01-30T18:00:00.000Z".to_string()),
                            ..Default::default()
                        })),
                    })
                },
            );
        })
    }

    #[tokio::test]
    async fn test_delete_attachment_returns_updated_cipher() {
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let api_client = mock_delete_attachment_success();
        let repository = MemoryRepository::<Cipher>::default();
        let cipher = create_cipher_fixture(cipher_id);
        repository
            .set(TEST_CIPHER_ID.to_string(), cipher.clone())
            .await
            .unwrap();

        let result = delete_attachment(
            api_client.ciphers_api(),
            &repository,
            cipher_id,
            TEST_ATTACHMENT_ID_TO_DELETE,
            false,
        )
        .await;

        assert!(result.is_ok());
        let updated_cipher = result.unwrap();
        let attachments = updated_cipher
            .attachments
            .as_ref()
            .expect("Attachments should exist");
        let stored_cipher = repository
            .get(TEST_CIPHER_ID.to_string())
            .await
            .unwrap()
            .expect("Cipher exists");
        let stored_attachments = stored_cipher
            .attachments
            .as_ref()
            .expect("Attachments exist");

        assert_eq!(attachments.len(), 1, "Should have 1 attachment remaining");
        assert_eq!(
            attachments[0].id.as_deref(),
            Some(TEST_ATTACHMENT_ID_TO_KEEP),
            "The remaining attachment should be the one we didn't delete"
        );

        assert_eq!(
            updated_cipher.revision_date.to_rfc3339(),
            "2024-01-30T18:00:00+00:00",
            "Revision date should be updated from API response"
        );

        assert_eq!(stored_attachments.len(), 1);

        assert_eq!(
            stored_attachments[0].id.as_deref(),
            Some(TEST_ATTACHMENT_ID_TO_KEEP),
            "Stored cipher should have the correct remaining attachment"
        );

        assert_eq!(stored_cipher.revision_date, updated_cipher.revision_date);

        assert_eq!(stored_cipher.name, cipher.name, "Name should not change");
    }

    #[tokio::test]
    async fn test_delete_attachment_uses_non_admin_api() {
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let api_client = mock_delete_attachment_success();
        let repository = MemoryRepository::<Cipher>::default();
        let cipher = create_cipher_fixture(cipher_id);
        repository
            .set(TEST_CIPHER_ID.to_string(), cipher.clone())
            .await
            .unwrap();

        let result = delete_attachment(
            api_client.ciphers_api(),
            &repository,
            cipher_id,
            TEST_ATTACHMENT_ID_TO_DELETE,
            false, // admin = false
        )
        .await;

        assert!(result.is_ok());
        let updated_cipher = result.unwrap();
        let attachments = updated_cipher
            .attachments
            .as_ref()
            .expect("Attachments should exist");
        assert_eq!(attachments.len(), 1, "Should have 1 attachment remaining");
        assert_eq!(
            attachments[0].id.as_deref(),
            Some(TEST_ATTACHMENT_ID_TO_KEEP)
        );
    }

    #[tokio::test]
    async fn test_delete_attachment_as_admin_client_method_fails_without_mock_server() {
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let api_client = mock_delete_attachment_admin_success();
        let repository = MemoryRepository::<Cipher>::default();
        let cipher = create_cipher_fixture(cipher_id);
        repository
            .set(TEST_CIPHER_ID.to_string(), cipher.clone())
            .await
            .unwrap();

        let result = delete_attachment(
            api_client.ciphers_api(),
            &repository,
            cipher_id,
            TEST_ATTACHMENT_ID_TO_DELETE,
            true, // admin = true
        )
        .await;

        assert!(result.is_ok());
        let updated_cipher = result.unwrap();
        let attachments = updated_cipher
            .attachments
            .as_ref()
            .expect("Attachments should exist");
        assert_eq!(attachments.len(), 1, "Should have 1 attachment remaining");
        assert_eq!(
            attachments[0].id.as_deref(),
            Some(TEST_ATTACHMENT_ID_TO_KEEP)
        );
    }

    #[tokio::test]
    async fn test_delete_attachment_missing_cipher_in_repository() {
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let api_client = mock_delete_attachment_success();
        let repository = MemoryRepository::<Cipher>::default();

        let result = delete_attachment(
            api_client.ciphers_api(),
            &repository,
            cipher_id,
            TEST_ATTACHMENT_ID_TO_DELETE,
            false,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CipherError::MissingField(_)));
    }

    #[tokio::test]
    async fn test_delete_attachment_api_error() {
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_delete_attachment()
                .returning(move |_id, _attachment_id| {
                    Err(bitwarden_api_api::apis::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "Attachment not found",
                    )))
                });
        });
        let repository = MemoryRepository::<Cipher>::default();
        let cipher = create_cipher_fixture(cipher_id);
        repository
            .set(TEST_CIPHER_ID.to_string(), cipher.clone())
            .await
            .unwrap();

        let result = delete_attachment(
            api_client.ciphers_api(),
            &repository,
            cipher_id,
            TEST_ATTACHMENT_ID_TO_DELETE,
            false,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_attachment_admin_api_error() {
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api.expect_delete_attachment_admin().returning(
                move |_id, _attachment_id| {
                    Err(bitwarden_api_api::apis::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "Attachment not found as admin",
                    )))
                },
            );
        });
        let repository = MemoryRepository::<Cipher>::default();
        let cipher = create_cipher_fixture(cipher_id);
        repository
            .set(TEST_CIPHER_ID.to_string(), cipher.clone())
            .await
            .unwrap();

        let result = delete_attachment(
            api_client.ciphers_api(),
            &repository,
            cipher_id,
            TEST_ATTACHMENT_ID_TO_DELETE,
            true,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_attachment_no_attachments_on_cipher() {
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let api_client = mock_delete_attachment_success();
        let repository = MemoryRepository::<Cipher>::default();
        let mut cipher = create_cipher_fixture(cipher_id);
        cipher.attachments = None;
        repository
            .set(TEST_CIPHER_ID.to_string(), cipher.clone())
            .await
            .unwrap();

        let result = delete_attachment(
            api_client.ciphers_api(),
            &repository,
            cipher_id,
            TEST_ATTACHMENT_ID_TO_DELETE,
            false,
        )
        .await;

        assert!(result.is_ok());
        let updated_cipher = result.unwrap();
        assert!(updated_cipher.attachments.is_none());
        assert_eq!(
            updated_cipher.revision_date.to_rfc3339(),
            "2024-01-30T18:00:00+00:00"
        );
    }
}
