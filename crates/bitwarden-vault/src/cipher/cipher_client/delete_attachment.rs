use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{Cipher, CipherId, CiphersClient, VaultParseError, cipher::cipher::PartialCipher};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CipherDeleteAttachmentError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for CipherDeleteAttachmentError {
    fn from(value: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(value.into())
    }
}

/// Deletes an attachment from a cipher, and updates the local repository with the new cipher data
/// returned from the API.
pub async fn delete_attachment<R: Repository<Cipher> + ?Sized>(
    cipher_id: CipherId,
    attachment_id: &str,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
) -> Result<Cipher, CipherDeleteAttachmentError> {
    let api = api_client.ciphers_api();

    let response = api
        .delete_attachment(cipher_id.into(), attachment_id)
        .await?;

    let existing_cipher = repository.get(cipher_id).await?;
    let cipher_response = response
        .cipher
        .map(|c| *c)
        .ok_or(MissingFieldError("cipher"))?;
    let cipher = cipher_response.merge_with_cipher(existing_cipher)?;

    repository.set(cipher_id, cipher.clone()).await?;

    Ok(cipher)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    /// Deletes an attachment from a cipher, and updates the local repository with the new cipher
    /// data returned from the API.
    pub async fn delete_attachment(
        &self,
        cipher_id: CipherId,
        attachment_id: String,
    ) -> Result<Cipher, CipherDeleteAttachmentError> {
        let configs = self.client.internal.get_api_configurations().await;
        delete_attachment(
            cipher_id,
            &attachment_id,
            &configs.api_client,
            &*self.get_repository()?,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{CipherMiniResponseModel, DeleteAttachmentResponseModel},
    };
    use bitwarden_state::repository::Repository;
    use bitwarden_test::MemoryRepository;

    use super::*;
    use crate::Attachment;

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_ATTACHMENT_ID: &str = "uf7bkexzag04d3cw04jsbqqkbpbwhxs0";

    fn generate_test_cipher() -> Cipher {
        Cipher {
            id: TEST_CIPHER_ID.parse().ok(),
            name: "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=".parse().unwrap(),
            r#type: crate::CipherType::Login,
            attachments: Some(vec![Attachment {
                id: Some(TEST_ATTACHMENT_ID.to_string()),
                url: Some("http://localhost:4000/attachments/test".to_string()),
                file_name: Some("2.mV50WiLq6duhwGbhM1TO0A==|dTufWNH8YTPP0EMlNLIpFA==|QHp+7OM8xHtEmCfc9QPXJ0Ro2BeakzvLgxJZ7NdLuDc=".parse().unwrap()),
                key: None,
                size: Some("65".to_string()),
                size_name: Some("65 Bytes".to_string()),
            }]),
            notes: Default::default(),
            organization_id: Default::default(),
            folder_id: Default::default(),
            favorite: Default::default(),
            reprompt: Default::default(),
            fields: Default::default(),
            collection_ids: Default::default(),
            key: Default::default(),
            login: Default::default(),
            identity: Default::default(),
            card: Default::default(),
            secure_note: Default::default(),
            ssh_key: Default::default(),
            organization_use_totp: Default::default(),
            edit: Default::default(),
            permissions: Default::default(),
            view_password: Default::default(),
            local_data: Default::default(),
            password_history: Default::default(),
            creation_date: Default::default(),
            deleted_date: Default::default(),
            revision_date: Default::default(),
            archived_date: Default::default(),
            data: Default::default(),
        }
    }

    #[tokio::test]
    async fn test_delete_attachment() {
        let cipher = generate_test_cipher();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_delete_attachment()
                .returning(move |id, attachment_id| {
                    assert_eq!(&id.to_string(), TEST_CIPHER_ID);
                    assert_eq!(attachment_id, TEST_ATTACHMENT_ID);
                    Ok(DeleteAttachmentResponseModel {
                        object: None,
                        cipher: Some(Box::new(CipherMiniResponseModel {
                            id: Some(TEST_CIPHER_ID.try_into().unwrap()),
                            name: Some("2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=".to_string()),
                            r#type: Some(bitwarden_api_api::models::CipherType::Login),
                            creation_date: Some("2024-05-31T11:20:58.4566667Z".to_string()),
                            revision_date: Some("2024-05-31T11:20:58.4566667Z".to_string()),
                            attachments: None,
                            ..Default::default()
                        })),
                    })
                });
        });

        let repository = MemoryRepository::<Cipher>::default();
        repository.set(cipher_id, cipher).await.unwrap();

        let result = delete_attachment(cipher_id, TEST_ATTACHMENT_ID, &api_client, &repository)
            .await
            .unwrap();

        // The returned cipher should have no attachments (API response had none)
        assert!(result.attachments.is_none());

        // Verify the repository was updated
        let repo_cipher = repository.get(cipher_id).await.unwrap().unwrap();
        assert!(repo_cipher.attachments.is_none());
    }

    #[tokio::test]
    async fn test_delete_attachment_missing_cipher_in_response() {
        let cipher = generate_test_cipher();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_delete_attachment()
                .returning(move |_id, _attachment_id| {
                    Ok(DeleteAttachmentResponseModel {
                        object: None,
                        cipher: None,
                    })
                });
        });

        let repository = MemoryRepository::<Cipher>::default();
        repository.set(cipher_id, cipher).await.unwrap();

        let result =
            delete_attachment(cipher_id, TEST_ATTACHMENT_ID, &api_client, &repository).await;

        assert!(
            result.is_err(),
            "Should fail when API response has no cipher"
        );
    }
}
