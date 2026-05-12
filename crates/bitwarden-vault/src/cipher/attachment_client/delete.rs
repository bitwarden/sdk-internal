use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError, RepositoryOption};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{AttachmentsClient, Cipher, CipherId, VaultParseError, cipher::cipher::PartialCipher};

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
impl AttachmentsClient {
    /// Deletes an attachment from a cipher, and updates the local repository with the new cipher
    /// data returned from the API.
    pub async fn delete_attachment(
        &self,
        cipher_id: CipherId,
        attachment_id: String,
    ) -> Result<Cipher, CipherDeleteAttachmentError> {
        delete_attachment(
            cipher_id,
            &attachment_id,
            &self.api_configurations.api_client,
            self.repository.require()?.as_ref(),
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
    use crate::{Attachment, CipherRepromptType, CipherType};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_ATTACHMENT_ID: &str = "uf7bkexzag04d3cw04jsbqqkbpbwhxs0";
    const TEST_CIPHER_NAME: &str = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";
    const TEST_FILE_NAME: &str = "2.mV50WiLq6duhwGbhM1TO0A==|dTufWNH8YTPP0EMlNLIpFA==|QHp+7OM8xHtEmCfc9QPXJ0Ro2BeakzvLgxJZ7NdLuDc=";

    fn test_cipher() -> Cipher {
        Cipher {
            id: TEST_CIPHER_ID.parse().ok(),
            name: TEST_CIPHER_NAME.parse().unwrap(),
            r#type: CipherType::Login,
            attachments: Some(vec![Attachment {
                id: Some(TEST_ATTACHMENT_ID.to_string()),
                url: Some("http://localhost:4000/attachments/test".to_string()),
                file_name: Some(TEST_FILE_NAME.parse().unwrap()),
                key: None,
                size: Some("65".to_string()),
                size_name: Some("65 Bytes".to_string()),
            }]),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            notes: None,
            login: None,
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            bank_account: None,
            drivers_license: None,
            passport: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: true,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            fields: None,
            password_history: None,
            creation_date: "2024-05-31T11:20:58.4566667Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-05-31T11:20:58.4566667Z".parse().unwrap(),
            archived_date: None,
            data: None,
        }
    }

    #[tokio::test]
    async fn returns_updated_cipher_on_success() {
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_delete_attachment()
                .returning(|id, attachment_id| {
                    assert_eq!(&id.to_string(), TEST_CIPHER_ID);
                    assert_eq!(attachment_id, TEST_ATTACHMENT_ID);
                    Ok(DeleteAttachmentResponseModel {
                        object: None,
                        cipher: Some(Box::new(CipherMiniResponseModel {
                            id: Some(TEST_CIPHER_ID.try_into().unwrap()),
                            name: Some(TEST_CIPHER_NAME.to_string()),
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
        repository.set(cipher_id, test_cipher()).await.unwrap();

        let result = delete_attachment(cipher_id, TEST_ATTACHMENT_ID, &api_client, &repository)
            .await
            .unwrap();

        assert!(result.attachments.is_none());

        let repo_cipher = repository.get(cipher_id).await.unwrap().unwrap();
        assert!(repo_cipher.attachments.is_none());
    }

    #[tokio::test]
    async fn errors_when_response_has_no_cipher() {
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_delete_attachment()
                .returning(|_id, _attachment_id| {
                    Ok(DeleteAttachmentResponseModel {
                        object: None,
                        cipher: None,
                    })
                });
        });

        let repository = MemoryRepository::<Cipher>::default();
        repository.set(cipher_id, test_cipher()).await.unwrap();

        let result =
            delete_attachment(cipher_id, TEST_ATTACHMENT_ID, &api_client, &repository).await;

        assert!(result.is_err());
    }
}
