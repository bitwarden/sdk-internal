use bitwarden_api_api::{apis::ApiClient, models::CipherBulkRestoreRequestModel};
use bitwarden_core::{ApiError, OrganizationId, key_management::KeyIds};
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use thiserror::Error;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    Cipher, CipherId, CipherView, DecryptCipherListResult, VaultParseError,
    cipher::cipher::PartialCipher, cipher_client::admin::CipherAdminClient,
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum RestoreCipherAdminError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for RestoreCipherAdminError {
    fn from(val: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(val.into())
    }
}

/// Restores a soft-deleted cipher on the server, using the admin endpoint.
pub async fn restore_as_admin(
    cipher_id: CipherId,
    api_client: &ApiClient,
    key_store: &KeyStore<KeyIds>,
) -> Result<CipherView, RestoreCipherAdminError> {
    let api = api_client.ciphers_api();

    let cipher: Cipher = api
        .put_restore_admin(cipher_id.into())
        .await?
        .merge_with_cipher(None)?;

    Ok(key_store.decrypt(&cipher)?)
}

/// Restores multiple soft-deleted ciphers on the server.
pub async fn restore_many_as_admin(
    cipher_ids: Vec<CipherId>,
    org_id: OrganizationId,
    api_client: &ApiClient,
    key_store: &KeyStore<KeyIds>,
) -> Result<DecryptCipherListResult, RestoreCipherAdminError> {
    let api = api_client.ciphers_api();

    let ciphers: Vec<Cipher> = api
        .put_restore_many_admin(Some(CipherBulkRestoreRequestModel {
            ids: cipher_ids.into_iter().map(|id| id.to_string()).collect(),
            organization_id: Some(org_id.into()),
        }))
        .await?
        .data
        .into_iter()
        .flatten()
        .map(|c| c.merge_with_cipher(None))
        .collect::<Result<Vec<_>, _>>()?;

    let (successes, failures) = key_store.decrypt_list_with_failures(&ciphers);
    Ok(DecryptCipherListResult {
        successes,
        failures: failures.into_iter().cloned().collect(),
    })
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CipherAdminClient {
    /// Restores a soft-deleted cipher on the server, using the admin endpoint.
    pub async fn restore(
        &self,
        cipher_id: CipherId,
    ) -> Result<CipherView, RestoreCipherAdminError> {
        let api_client = &self
            .client
            .internal
            .get_api_configurations()
            .await
            .api_client;
        let key_store = self.client.internal.get_key_store();

        restore_as_admin(cipher_id, api_client, key_store).await
    }
    /// Restores multiple soft-deleted ciphers on the server.
    pub async fn restore_many(
        &self,
        cipher_ids: Vec<CipherId>,
        org_id: OrganizationId,
    ) -> Result<DecryptCipherListResult, RestoreCipherAdminError> {
        let api_client = &self
            .client
            .internal
            .get_api_configurations()
            .await
            .api_client;
        let key_store = self.client.internal.get_key_store();

        restore_many_as_admin(cipher_ids, org_id, api_client, key_store).await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{CipherMiniResponseModel, CipherMiniResponseModelListResponseModel},
    };
    use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey};
    use chrono::Utc;

    use super::*;
    use crate::{Cipher, CipherId, Login};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_CIPHER_ID_2: &str = "6faa9684-c793-4a2d-8a12-b33900187098";
    const TEST_ORG_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";

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
    async fn test_restore_as_admin() {
        let mut cipher = generate_test_cipher();
        cipher.deleted_date = Some(Utc::now());

        let api_client = {
            let cipher = cipher.clone();
            ApiClient::new_mocked(move |mock| {
                mock.ciphers_api
                    .expect_put_restore_admin()
                    .returning(move |_model| {
                        Ok(CipherMiniResponseModel {
                            id: Some(TEST_CIPHER_ID.try_into().unwrap()),
                            name: Some(cipher.name.to_string()),
                            r#type: Some(cipher.r#type.into()),
                            creation_date: Some(cipher.creation_date.to_string()),
                            revision_date: Some(Utc::now().to_rfc3339()),
                            login: cipher.login.clone().map(|l| Box::new(l.into())),
                            ..Default::default()
                        })
                    });
            })
        };

        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );
        let start_time = Utc::now();
        let updated_cipher = restore_as_admin(TEST_CIPHER_ID.parse().unwrap(), &api_client, &store)
            .await
            .unwrap();
        let end_time = Utc::now();

        assert!(updated_cipher.deleted_date.is_none());
        assert!(
            updated_cipher.revision_date >= start_time && updated_cipher.revision_date <= end_time
        );
    }

    #[tokio::test]
    async fn test_restore_many_as_admin() {
        let cipher_id_2: CipherId = TEST_CIPHER_ID_2.parse().unwrap();
        let mut cipher_1 = generate_test_cipher();
        cipher_1.deleted_date = Some(Utc::now());
        let mut cipher_2 = generate_test_cipher();
        cipher_2.deleted_date = Some(Utc::now());
        cipher_2.id = Some(cipher_id_2);

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_put_restore_many_admin()
                .returning(move |_model| {
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
                                revision_date: Some(Utc::now().to_rfc3339()),
                                ..Default::default()
                            },
                            CipherMiniResponseModel {
                                id: cipher_2.id.map(|id| id.into()),
                                name: Some(cipher_2.name.to_string()),
                                r#type: Some(cipher_2.r#type.into()),
                                login: cipher_2.login.clone().map(|l| Box::new(l.into())),
                                creation_date: cipher_2.creation_date.to_string().into(),
                                deleted_date: None,
                                revision_date: Some(Utc::now().to_rfc3339()),
                                ..Default::default()
                            },
                        ]),
                        continuation_token: None,
                    })
                });
        });
        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let start_time = Utc::now();
        let ciphers = restore_many_as_admin(
            vec![
                TEST_CIPHER_ID.parse().unwrap(),
                TEST_CIPHER_ID_2.parse().unwrap(),
            ],
            TEST_ORG_ID.parse().unwrap(),
            &api_client,
            &store,
        )
        .await
        .unwrap();
        let end_time = Utc::now();

        assert_eq!(ciphers.successes.len(), 2,);
        assert_eq!(ciphers.failures.len(), 0,);
        assert_eq!(
            ciphers.successes[0].id,
            Some(TEST_CIPHER_ID.parse().unwrap()),
        );
        assert_eq!(
            ciphers.successes[1].id,
            Some(TEST_CIPHER_ID_2.parse().unwrap()),
        );
        assert_eq!(ciphers.successes[0].deleted_date, None,);
        assert_eq!(ciphers.successes[1].deleted_date, None,);

        assert!(
            ciphers.successes[0].revision_date >= start_time
                && ciphers.successes[0].revision_date <= end_time
        );
        assert!(
            ciphers.successes[1].revision_date >= start_time
                && ciphers.successes[1].revision_date <= end_time
        );
    }
}
