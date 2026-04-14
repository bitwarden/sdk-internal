use bitwarden_api_api::{apis::ApiClient, models::CipherBulkRestoreRequestModel};
use bitwarden_core::{ApiError, key_management::KeySlotIds};
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use futures::future::OptionFuture;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    Cipher, CipherId, CipherView, CiphersClient, DecryptCipherListResult, VaultParseError,
    cipher::cipher::{PartialCipher, StrictDecrypt},
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum RestoreCipherError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for RestoreCipherError {
    fn from(val: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(val.into())
    }
}

/// Restores a soft-deleted cipher on the server.
pub async fn restore<R: Repository<Cipher> + ?Sized>(
    cipher_id: CipherId,
    api_client: &ApiClient,
    repository: &R,
    key_store: &KeyStore<KeySlotIds>,
    use_strict_decryption: bool,
) -> Result<CipherView, RestoreCipherError> {
    let api = api_client.ciphers_api();

    let existing_cipher = repository.get(cipher_id).await?;
    let cipher: Cipher = api
        .put_restore(cipher_id.into())
        .await?
        .merge_with_cipher(existing_cipher)?;
    repository.set(cipher_id, cipher.clone()).await?;

    if use_strict_decryption {
        Ok(key_store.decrypt(&StrictDecrypt(cipher))?)
    } else {
        Ok(key_store.decrypt(&cipher)?)
    }
}

/// Restores multiple soft-deleted ciphers on the server.
pub async fn restore_many<R: Repository<Cipher> + ?Sized>(
    cipher_ids: Vec<CipherId>,
    api_client: &ApiClient,
    repository: &R,
    key_store: &KeyStore<KeySlotIds>,
) -> Result<DecryptCipherListResult, RestoreCipherError> {
    let api = api_client.ciphers_api();

    let response_models: Vec<_> = api
        .put_restore_many(Some(CipherBulkRestoreRequestModel {
            ids: cipher_ids.into_iter().map(|id| id.to_string()).collect(),
            organization_id: None,
        }))
        .await?
        .data
        .into_iter()
        .flatten()
        .collect();

    let mut ciphers = Vec::with_capacity(response_models.len());
    for model in response_models {
        let existing = OptionFuture::from(model.id.map(|id| repository.get(CipherId::new(id))))
            .await
            .transpose()?
            .flatten();
        ciphers.push(model.merge_with_cipher(existing)?);
    }

    for cipher in &ciphers {
        if let Some(id) = cipher.id {
            repository.set(id, cipher.clone()).await?;
        }
    }

    let (successes, failures) = key_store.decrypt_list_with_failures(&ciphers);
    Ok(DecryptCipherListResult {
        successes,
        failures: failures.into_iter().cloned().collect(),
    })
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    /// Restores a soft-deleted cipher on the server.
    pub async fn restore(&self, cipher_id: CipherId) -> Result<CipherView, RestoreCipherError> {
        let api_client = &self.client.internal.get_api_configurations().api_client;
        let key_store = self.client.internal.get_key_store();

        restore(
            cipher_id,
            api_client,
            &*self.get_repository()?,
            key_store,
            self.is_strict_decrypt().await,
        )
        .await
    }

    /// Restores multiple soft-deleted ciphers on the server.
    pub async fn restore_many(
        &self,
        cipher_ids: Vec<CipherId>,
    ) -> Result<DecryptCipherListResult, RestoreCipherError> {
        let api_client = &self.client.internal.get_api_configurations().api_client;
        let key_store = self.client.internal.get_key_store();
        let repository = &*self.get_repository()?;

        restore_many(cipher_ids, api_client, repository, key_store).await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            CipherMiniResponseModel, CipherMiniResponseModelListResponseModel, CipherResponseModel,
        },
    };
    use bitwarden_collections::collection::CollectionId;
    use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey};
    use bitwarden_state::repository::Repository;
    use bitwarden_test::MemoryRepository;
    use chrono::Utc;

    use super::*;
    use crate::{Cipher, CipherId, Login};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_CIPHER_ID_2: &str = "6faa9684-c793-4a2d-8a12-b33900187098";

    fn setup_key_store() -> KeyStore<KeySlotIds> {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeySlotId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );
        store
    }

    fn generate_test_cipher() -> Cipher {
        Cipher {
            id: TEST_CIPHER_ID.parse().ok(),
            name: "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=".parse().unwrap(),
            r#type: crate::CipherType::Login,
            notes: Default::default(),
            organization_id: Default::default(),
            folder_id: Default::default(),
            favorite: Default::default(),
            reprompt: Default::default(),
            fields: Default::default(),
            collection_ids: Default::default(),
            key: Default::default(),
            login: Some(Login{
                username: None,
                password: None,
                password_revision_date: None,
                uris: None, totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            identity: Default::default(),
            card: Default::default(),
            secure_note: Default::default(),
            ssh_key: Default::default(),
            organization_use_totp: Default::default(),
            edit: Default::default(),
            permissions: Default::default(),
            view_password: Default::default(),
            local_data: Default::default(),
            attachments: Default::default(),
            password_history: Default::default(),
            creation_date: Default::default(),
            deleted_date: Default::default(),
            revision_date: Default::default(),
            archived_date: Default::default(),
            data: Default::default(),
        }
    }

    #[tokio::test]
    async fn test_restore() {
        // Set up test ciphers in the repository.
        let mut cipher_1 = generate_test_cipher();
        cipher_1.deleted_date = Some(Utc::now());

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_put_restore()
                .returning(move |_model| {
                    Ok(CipherResponseModel {
                        id: Some(TEST_CIPHER_ID.try_into().unwrap()),
                        name: Some(cipher_1.name.to_string()),
                        r#type: Some(cipher_1.r#type.into()),
                        creation_date: Some(cipher_1.creation_date.to_string()),
                        revision_date: Some(Utc::now().to_string()),
                        ..Default::default()
                    })
                });
        });

        let repository: MemoryRepository<Cipher> = Default::default();
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeySlotId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let collection_id: CollectionId = "a4e13cc0-1234-5678-abcd-b181009709b8".parse().unwrap();
        let mut cipher = generate_test_cipher();
        cipher.deleted_date = Some(Utc::now());
        cipher.collection_ids = vec![collection_id];

        repository
            .set(TEST_CIPHER_ID.parse().unwrap(), cipher)
            .await
            .unwrap();

        let start_time = Utc::now();
        let updated_cipher = restore(
            TEST_CIPHER_ID.parse().unwrap(),
            &api_client,
            &repository,
            &store,
            false,
        )
        .await
        .unwrap();

        let end_time = Utc::now();
        assert!(updated_cipher.deleted_date.is_none());
        assert!(
            updated_cipher.revision_date >= start_time && updated_cipher.revision_date <= end_time
        );
        // collection_ids are not returned by the server's restore response — they must be
        // preserved.
        assert_eq!(updated_cipher.collection_ids, vec![collection_id]);

        let repo_cipher = repository
            .get(TEST_CIPHER_ID.parse().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(repo_cipher.deleted_date.is_none());
        assert!(
            repo_cipher.revision_date >= start_time && updated_cipher.revision_date <= end_time
        );
    }

    #[tokio::test]
    async fn test_restore_many() {
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let cipher_id_2: CipherId = TEST_CIPHER_ID_2.parse().unwrap();
        let collection_id: CollectionId = "a4e13cc0-1234-5678-abcd-b181009709b8".parse().unwrap();
        let collection_id_2: CollectionId = "b5e13cc0-1234-5678-abcd-b181009709b8".parse().unwrap();
        let mut cipher_1 = generate_test_cipher();
        cipher_1.deleted_date = Some(Utc::now());
        cipher_1.collection_ids = vec![collection_id];
        let mut cipher_2 = generate_test_cipher();
        cipher_2.deleted_date = Some(Utc::now());
        cipher_2.id = Some(cipher_id_2);
        cipher_2.collection_ids = vec![collection_id_2];

        let api_client = {
            let cipher_1 = cipher_1.clone();
            let cipher_2 = cipher_2.clone();
            ApiClient::new_mocked(move |mock| {
                mock.ciphers_api.expect_put_restore_many().returning({
                    move |_model| {
                        Ok(CipherMiniResponseModelListResponseModel {
                            object: None,
                            data: Some(vec![
                                CipherMiniResponseModel {
                                    id: cipher_1.id.map(|id| id.into()),
                                    name: Some(cipher_1.name.to_string()),
                                    r#type: Some(cipher_1.r#type.into()),
                                    login: cipher_1.login.clone().map(|l| Box::new(l.into())),
                                    creation_date: cipher_1.creation_date.to_string().into(),
                                    deleted_date: None,
                                    revision_date: Some(Utc::now().to_string()),
                                    ..Default::default()
                                },
                                CipherMiniResponseModel {
                                    id: cipher_2.id.map(|id| id.into()),
                                    name: Some(cipher_2.name.to_string()),
                                    r#type: Some(cipher_2.r#type.into()),
                                    login: cipher_2.login.clone().map(|l| Box::new(l.into())),
                                    creation_date: cipher_2.creation_date.to_string().into(),
                                    deleted_date: None,
                                    revision_date: Some(Utc::now().to_string()),
                                    ..Default::default()
                                },
                            ]),
                            continuation_token: None,
                        })
                    }
                });
            })
        };

        let repository: MemoryRepository<Cipher> = Default::default();
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeySlotId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        repository.set(cipher_id, cipher_1).await.unwrap();
        repository.set(cipher_id_2, cipher_2).await.unwrap();

        let start_time = Utc::now();
        let ciphers = restore_many(
            vec![cipher_id, cipher_id_2],
            &api_client,
            &repository,
            &store,
        )
        .await
        .unwrap();
        let end_time = Utc::now();

        assert_eq!(ciphers.successes.len(), 2,);
        assert_eq!(ciphers.failures.len(), 0,);
        assert_eq!(ciphers.successes[0].deleted_date, None,);
        assert_eq!(ciphers.successes[1].deleted_date, None,);

        // Confirm repository was updated
        let cipher_1 = repository.get(cipher_id).await.unwrap().unwrap();
        let cipher_2 = repository.get(cipher_id_2).await.unwrap().unwrap();
        assert!(cipher_1.deleted_date.is_none());
        assert!(cipher_2.deleted_date.is_none());
        assert!(cipher_1.revision_date >= start_time && cipher_1.revision_date <= end_time);
        assert!(cipher_2.revision_date >= start_time && cipher_2.revision_date <= end_time);
    }

    #[tokio::test]
    async fn test_restore_preserves_collection_ids() {
        let store = setup_key_store();
        let collection_id: CollectionId = "a4e13cc0-1234-5678-abcd-b181009709b8".parse().unwrap();

        let mut cipher = generate_test_cipher();
        cipher.deleted_date = Some(Utc::now());
        cipher.collection_ids = vec![collection_id];

        let cipher_name = cipher.name.to_string();
        let cipher_type = cipher.r#type;

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api.expect_put_restore().returning(move |_| {
                Ok(CipherResponseModel {
                    id: Some(TEST_CIPHER_ID.try_into().unwrap()),
                    name: Some(cipher_name.clone()),
                    r#type: Some(cipher_type.into()),
                    creation_date: Some("2025-01-01T00:00:00Z".to_string()),
                    revision_date: Some(Utc::now().to_string()),
                    ..Default::default()
                })
            });
        });

        let repository: MemoryRepository<Cipher> = Default::default();
        repository
            .set(TEST_CIPHER_ID.parse().unwrap(), cipher)
            .await
            .unwrap();

        let result = restore(
            TEST_CIPHER_ID.parse().unwrap(),
            &api_client,
            &repository,
            &store,
            false,
        )
        .await
        .unwrap();

        // collection_ids are not returned by the server's restore response — they must
        // be preserved from the existing cipher in the repository.
        assert_eq!(result.collection_ids, vec![collection_id]);
    }

    #[tokio::test]
    async fn test_restore_many_preserves_collection_ids() {
        let store = setup_key_store();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let cipher_id_2: CipherId = TEST_CIPHER_ID_2.parse().unwrap();
        let collection_id: CollectionId = "a4e13cc0-1234-5678-abcd-b181009709b8".parse().unwrap();
        let collection_id_2: CollectionId = "b5e13cc0-1234-5678-abcd-b181009709b8".parse().unwrap();

        let mut cipher_1 = generate_test_cipher();
        cipher_1.deleted_date = Some(Utc::now());
        cipher_1.collection_ids = vec![collection_id];

        let mut cipher_2 = generate_test_cipher();
        cipher_2.id = Some(cipher_id_2);
        cipher_2.deleted_date = Some(Utc::now());
        cipher_2.collection_ids = vec![collection_id_2];

        let api_client = {
            let cipher_1 = cipher_1.clone();
            let cipher_2 = cipher_2.clone();
            ApiClient::new_mocked(move |mock| {
                mock.ciphers_api.expect_put_restore_many().returning({
                    move |_| {
                        Ok(CipherMiniResponseModelListResponseModel {
                            object: None,
                            data: Some(vec![
                                CipherMiniResponseModel {
                                    id: cipher_1.id.map(|id| id.into()),
                                    name: Some(cipher_1.name.to_string()),
                                    r#type: Some(cipher_1.r#type.into()),
                                    login: cipher_1.login.clone().map(|l| Box::new(l.into())),
                                    creation_date: cipher_1.creation_date.to_string().into(),
                                    deleted_date: None,
                                    revision_date: Some(Utc::now().to_string()),
                                    ..Default::default()
                                },
                                CipherMiniResponseModel {
                                    id: cipher_2.id.map(|id| id.into()),
                                    name: Some(cipher_2.name.to_string()),
                                    r#type: Some(cipher_2.r#type.into()),
                                    login: cipher_2.login.clone().map(|l| Box::new(l.into())),
                                    creation_date: cipher_2.creation_date.to_string().into(),
                                    deleted_date: None,
                                    revision_date: Some(Utc::now().to_string()),
                                    ..Default::default()
                                },
                            ]),
                            continuation_token: None,
                        })
                    }
                });
            })
        };

        let repository: MemoryRepository<Cipher> = Default::default();
        repository.set(cipher_id, cipher_1).await.unwrap();
        repository.set(cipher_id_2, cipher_2).await.unwrap();

        let ciphers = restore_many(
            vec![cipher_id, cipher_id_2],
            &api_client,
            &repository,
            &store,
        )
        .await
        .unwrap();

        assert_eq!(ciphers.successes.len(), 2);

        // collection_ids are not returned by the server's restore response — they must
        // be preserved from the existing ciphers in the repository.
        let result_1 = ciphers
            .successes
            .iter()
            .find(|c| c.id == Some(cipher_id))
            .unwrap();
        let result_2 = ciphers
            .successes
            .iter()
            .find(|c| c.id == Some(cipher_id_2))
            .unwrap();
        assert_eq!(result_1.collection_ids, vec![collection_id]);
        assert_eq!(result_2.collection_ids, vec![collection_id_2]);
    }
}
