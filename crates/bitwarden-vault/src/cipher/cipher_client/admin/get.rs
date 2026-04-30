use bitwarden_core::{ApiError, OrganizationId};
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    VaultParseError,
    cipher::cipher::{ListOrganizationCiphersResult, PartialCipher},
    cipher_client::admin::CipherAdminClient,
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum GetAssignedOrgCiphersAdminError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for GetAssignedOrgCiphersAdminError {
    fn from(value: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(value.into())
    }
}

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum GetOrganizationCiphersAdminError {
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    #[error(transparent)]
    Api(#[from] ApiError),
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for GetOrganizationCiphersAdminError {
    fn from(value: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(value.into())
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CipherAdminClient {
    /// Fetches and decrypts all ciphers assigned to the current user for an organization.
    pub async fn list_assigned_org_ciphers(
        &self,
        org_id: OrganizationId,
    ) -> Result<ListOrganizationCiphersResult, GetAssignedOrgCiphersAdminError> {
        use bitwarden_api_api::models::CipherDetailsResponseModelListResponseModel;

        let response: CipherDetailsResponseModelListResponseModel = self
            .api_configurations
            .api_client
            .ciphers_api()
            .get_assigned_organization_ciphers(Some(org_id.into()))
            .await?;

        let ciphers = response
            .data
            .into_iter()
            .flatten()
            .map(|model| model.merge_with_cipher(None))
            .collect::<Result<Vec<_>, _>>()?;

        let (list_views, _failures) = self.key_store.decrypt_list_with_failures(&ciphers);
        Ok(ListOrganizationCiphersResult {
            ciphers,
            list_views,
        })
    }

    /// Get all ciphers for an organization.
    pub async fn list_org_ciphers(
        &self,
        org_id: OrganizationId,
        include_member_items: bool,
    ) -> Result<ListOrganizationCiphersResult, GetOrganizationCiphersAdminError> {
        use bitwarden_api_api::models::CipherMiniDetailsResponseModelListResponseModel;

        let response: CipherMiniDetailsResponseModelListResponseModel = self
            .api_configurations
            .api_client
            .ciphers_api()
            .get_organization_ciphers(Some(org_id.into()), Some(include_member_items))
            .await?;

        let ciphers = response
            .data
            .into_iter()
            .flatten()
            .map(|model| model.merge_with_cipher(None))
            .collect::<Result<Vec<_>, _>>()?;

        let (list_views, _failures) = self.key_store.decrypt_list_with_failures(&ciphers);
        Ok(ListOrganizationCiphersResult {
            ciphers,
            list_views,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            CipherDetailsResponseModel, CipherDetailsResponseModelListResponseModel,
            CipherMiniDetailsResponseModel, CipherMiniDetailsResponseModelListResponseModel,
        },
    };
    use bitwarden_core::{
        client::ApiConfigurations,
        key_management::{KeySlotIds, SymmetricKeySlotId, create_test_crypto_with_user_key},
    };
    use bitwarden_crypto::SymmetricCryptoKey;
    use chrono::Utc;

    use super::*;
    use crate::{Cipher, CipherType, Login};

    const TEST_ORG_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";
    const TEST_CIPHER_ID_1: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_CIPHER_ID_2: &str = "6faa9684-c793-4a2d-8a12-b33900187098";

    fn create_test_client(api_client: ApiClient) -> CipherAdminClient {
        #[allow(deprecated)]
        CipherAdminClient {
            key_store: create_test_crypto_with_user_key(
                SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
            ),
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
            client: bitwarden_core::Client::new_test(None),
        }
    }

    fn mock_mini_cipher(cipher_id: &str) -> CipherMiniDetailsResponseModel {
        let cipher = generate_test_cipher();
        CipherMiniDetailsResponseModel {
            id: cipher_id.parse().ok(),
            name: Some(cipher.name.to_string()),
            r#type: Some(cipher.r#type.into()),
            login: cipher.login.clone().map(|l| Box::new(l.into())),
            creation_date: Some(Utc::now().to_rfc3339()),
            revision_date: Some(Utc::now().to_rfc3339()),
            ..Default::default()
        }
    }

    fn mock_details_cipher(cipher_id: &str) -> CipherDetailsResponseModel {
        CipherDetailsResponseModel {
            id: Some(cipher_id.parse().unwrap()),
            name: Some("2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=".to_string()),
            r#type: Some(bitwarden_api_api::models::CipherType::Login),
            login: Some(Box::new(bitwarden_api_api::models::CipherLoginModel::default())),
            creation_date: Some(Utc::now().to_rfc3339()),
            revision_date: Some(Utc::now().to_rfc3339()),
            ..Default::default()
        }
    }

    fn generate_test_cipher() -> Cipher {
        Cipher {
            id: TEST_CIPHER_ID_1.parse().ok(),
            name: "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=".parse().unwrap(),
            r#type: CipherType::Login,
            notes: Default::default(),
            organization_id: Default::default(),
            folder_id: Default::default(),
            favorite: Default::default(),
            reprompt: Default::default(),
            fields: Default::default(),
            collection_ids: Default::default(),
            key: Default::default(),
            login: Some(Login {
                username: None,
                password: None,
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            identity: Default::default(),
            card: Default::default(),
            secure_note: Default::default(),
            ssh_key: Default::default(),
            bank_account: Default::default(),
            drivers_license: Default::default(),
            passport: Default::default(),
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
    async fn test_list_org_ciphers_all_success() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_get_organization_ciphers()
                .returning(move |_org_id, _include_member_items| {
                    Ok(CipherMiniDetailsResponseModelListResponseModel {
                        object: None,
                        data: Some(vec![
                            mock_mini_cipher(TEST_CIPHER_ID_1),
                            mock_mini_cipher(TEST_CIPHER_ID_2),
                        ]),
                        continuation_token: None,
                    })
                });
        });

        let client = create_test_client(api_client);
        let result = client
            .list_org_ciphers(TEST_ORG_ID.parse().unwrap(), true)
            .await
            .unwrap();

        assert_eq!(result.ciphers.len(), 2);
        assert_eq!(result.list_views.len(), 2);
        assert_eq!(result.ciphers[0].id, TEST_CIPHER_ID_1.parse().ok());
        assert_eq!(result.ciphers[1].id, TEST_CIPHER_ID_2.parse().ok());
    }

    #[tokio::test]
    async fn test_list_org_ciphers_with_failures() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_get_organization_ciphers()
                .returning(move |_org_id, _include_member_items| {
                    let mut bad = mock_mini_cipher(TEST_CIPHER_ID_2);
                    bad.key = Some("2.Gg8yCM4IIgykCZyq0O4+cA==|GJLBtfvSJTDJh/F7X4cJPkzI6ccnzJm5DYl3yxOW2iUn7DgkkmzoOe61sUhC5dgVdV0kFqsZPcQ0yehlN1DDsFIFtrb4x7LwzJNIkMgxNyg=|1rGkGJ8zcM5o5D0aIIwAyLsjMLrPsP3EWm3CctBO3Fw=".to_string());
                    Ok(CipherMiniDetailsResponseModelListResponseModel {
                        object: None,
                        data: Some(vec![mock_mini_cipher(TEST_CIPHER_ID_1), bad]),
                        continuation_token: None,
                    })
                });
        });

        let client = create_test_client(api_client);
        let result = client
            .list_org_ciphers(TEST_ORG_ID.parse().unwrap(), true)
            .await
            .unwrap();

        assert_eq!(result.ciphers.len(), 2);
        assert_eq!(result.list_views.len(), 1);
    }

    #[tokio::test]
    async fn test_list_org_ciphers_empty() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_get_organization_ciphers()
                .returning(move |_org_id, _include_member_items| {
                    Ok(CipherMiniDetailsResponseModelListResponseModel {
                        object: None,
                        data: Some(vec![]),
                        continuation_token: None,
                    })
                });
        });

        let client = create_test_client(api_client);
        let result = client
            .list_org_ciphers(TEST_ORG_ID.parse().unwrap(), false)
            .await
            .unwrap();

        assert!(result.ciphers.is_empty());
        assert!(result.list_views.is_empty());
    }

    #[tokio::test]
    async fn test_list_assigned_org_ciphers_success() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_get_assigned_organization_ciphers()
                .returning(|_| {
                    Ok(CipherDetailsResponseModelListResponseModel {
                        object: None,
                        data: Some(vec![
                            mock_details_cipher(TEST_CIPHER_ID_1),
                            mock_details_cipher(TEST_CIPHER_ID_2),
                        ]),
                        continuation_token: None,
                    })
                });
        });

        let client = create_test_client(api_client);
        let result = client
            .list_assigned_org_ciphers(TEST_ORG_ID.parse().unwrap())
            .await
            .unwrap();

        assert_eq!(result.ciphers.len(), 2);
        assert_eq!(result.list_views.len(), 2);
    }

    #[tokio::test]
    async fn test_list_assigned_org_ciphers_with_failures() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_get_assigned_organization_ciphers()
                .returning(|_| {
                    let mut bad = mock_details_cipher(TEST_CIPHER_ID_2);
                    bad.key = Some("2.Gg8yCM4IIgykCZyq0O4+cA==|GJLBtfvSJTDJh/F7X4cJPkzI6ccnzJm5DYl3yxOW2iUn7DgkkmzoOe61sUhC5dgVdV0kFqsZPcQ0yehlN1DDsFIFtrb4x7LwzJNIkMgxNyg=|1rGkGJ8zcM5o5D0aIIwAyLsjMLrPsP3EWm3CctBO3Fw=".to_string());
                    Ok(CipherDetailsResponseModelListResponseModel {
                        object: None,
                        data: Some(vec![mock_details_cipher(TEST_CIPHER_ID_1), bad]),
                        continuation_token: None,
                    })
                });
        });

        let client = create_test_client(api_client);
        let result = client
            .list_assigned_org_ciphers(TEST_ORG_ID.parse().unwrap())
            .await
            .unwrap();

        assert_eq!(result.ciphers.len(), 2);
        assert_eq!(result.list_views.len(), 1);
        assert_eq!(result.list_views[0].id, TEST_CIPHER_ID_1.parse().ok());
    }

    #[tokio::test]
    async fn test_list_assigned_org_ciphers_empty() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_get_assigned_organization_ciphers()
                .returning(|_| {
                    Ok(CipherDetailsResponseModelListResponseModel {
                        object: None,
                        data: Some(vec![]),
                        continuation_token: None,
                    })
                });
        });

        let client = create_test_client(api_client);
        let result = client
            .list_assigned_org_ciphers(TEST_ORG_ID.parse().unwrap())
            .await
            .unwrap();

        assert!(result.ciphers.is_empty());
        assert!(result.list_views.is_empty());
    }
}
