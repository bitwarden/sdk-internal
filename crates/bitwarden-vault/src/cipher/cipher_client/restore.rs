use bitwarden_api_api::{apis::ApiClient, models::CipherBulkRestoreRequestModel};
use bitwarden_core::{ApiError, key_management::KeyIds};
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;

use crate::{
    Cipher, CipherId, CipherView, CiphersClient, DecryptCipherListResult, VaultParseError,
    cipher::cipher::PartialCipher,
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
pub async fn restore(
    cipher_id: CipherId,
    api_client: &ApiClient,
    repository: &(impl Repository<Cipher> + ?Sized),
    key_store: &KeyStore<KeyIds>,
) -> Result<CipherView, RestoreCipherError> {
    let api = api_client.ciphers_api();

    let cipher: Cipher = api.put_restore(cipher_id.into()).await?.try_into()?;
    repository
        .set(cipher_id.to_string(), cipher.clone())
        .await?;

    Ok(key_store.decrypt(&cipher)?)
}

/// Restores multiple soft-deleted ciphers on the server.
pub async fn restore_many(
    cipher_ids: Vec<CipherId>,
    api_client: &ApiClient,
    repository: &(impl Repository<Cipher> + ?Sized),
    key_store: &KeyStore<KeyIds>,
) -> Result<DecryptCipherListResult, RestoreCipherError> {
    let api = api_client.ciphers_api();

    let ciphers: Vec<Cipher> = api
        .put_restore_many(Some(CipherBulkRestoreRequestModel {
            ids: cipher_ids.into_iter().map(|id| id.to_string()).collect(),
            organization_id: None,
        }))
        .await?
        .data
        .into_iter()
        .flatten()
        .map(|c| c.merge_with_cipher(None))
        .collect::<Result<Vec<Cipher>, _>>()?;

    for cipher in &ciphers {
        if let Some(id) = &cipher.id {
            repository.set(id.to_string(), cipher.clone()).await?;
        }
    }

    let (successes, failures) = key_store.decrypt_list_with_failures(&ciphers);
    Ok(DecryptCipherListResult {
        successes,
        failures: failures.into_iter().cloned().collect(),
    })
}

impl CiphersClient {
    /// Restores a soft-deleted cipher on the server.
    pub async fn restore(&self, cipher_id: CipherId) -> Result<CipherView, RestoreCipherError> {
        let api_client = &self
            .client
            .internal
            .get_api_configurations()
            .await
            .api_client;
        let key_store = self.client.internal.get_key_store();

        restore(cipher_id, api_client, &*self.get_repository()?, key_store).await
    }

    /// Restores multiple soft-deleted ciphers on the server.
    pub async fn restore_many(
        &self,
        cipher_ids: Vec<CipherId>,
    ) -> Result<DecryptCipherListResult, RestoreCipherError> {
        let api_client = &self
            .client
            .internal
            .get_api_configurations()
            .await
            .api_client;
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
    use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey};
    use bitwarden_state::repository::Repository;
    use bitwarden_test::MemoryRepository;
    use chrono::Utc;

    use super::*;
    use crate::{Cipher, CipherId, Login};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_CIPHER_ID_2: &str = "6faa9684-c793-4a2d-8a12-b33900187098";

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
        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let mut cipher = generate_test_cipher();
        cipher.deleted_date = Some(Utc::now());

        repository
            .set(TEST_CIPHER_ID.to_string(), cipher)
            .await
            .unwrap();

        let start_time = Utc::now();
        let updated_cipher = restore(
            TEST_CIPHER_ID.parse().unwrap(),
            &api_client,
            &repository,
            &store,
        )
        .await
        .unwrap();

        let end_time = Utc::now();
        assert!(updated_cipher.deleted_date.is_none());
        assert!(
            updated_cipher.revision_date >= start_time && updated_cipher.revision_date <= end_time
        );

        let repo_cipher = repository
            .get(TEST_CIPHER_ID.to_string())
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
        let mut cipher_1 = generate_test_cipher();
        cipher_1.deleted_date = Some(Utc::now());
        let mut cipher_2 = generate_test_cipher();
        cipher_2.deleted_date = Some(Utc::now());
        cipher_2.id = Some(cipher_id_2);

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
        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        repository
            .set(cipher_id.to_string(), cipher_1)
            .await
            .unwrap();
        repository
            .set(TEST_CIPHER_ID_2.to_string(), cipher_2)
            .await
            .unwrap();

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
        let cipher_1 = repository
            .get(cipher_id.to_string())
            .await
            .unwrap()
            .unwrap();
        let cipher_2 = repository
            .get(cipher_id_2.to_string())
            .await
            .unwrap()
            .unwrap();
        assert!(cipher_1.deleted_date.is_none());
        assert!(cipher_2.deleted_date.is_none());
        assert!(cipher_1.revision_date >= start_time && cipher_1.revision_date <= end_time);
        assert!(cipher_2.revision_date >= start_time && cipher_2.revision_date <= end_time);
    }
}
