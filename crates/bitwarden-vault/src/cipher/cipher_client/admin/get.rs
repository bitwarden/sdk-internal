use bitwarden_api_api::models::CipherMiniDetailsResponseModelListResponseModel;
use bitwarden_core::{ApiError, OrganizationId, key_management::KeyIds};
use bitwarden_crypto::{CryptoError, KeyStore};
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
pub enum GetOrganizationCiphersAdminError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    #[error(transparent)]
    Api(#[from] ApiError),
}

/// Get all ciphers for an organization.
pub async fn list_org_ciphers(
    org_id: OrganizationId,
    include_member_items: bool,
    api_client: &bitwarden_api_api::apis::ApiClient,
    key_store: &KeyStore<KeyIds>,
) -> Result<ListOrganizationCiphersResult, GetOrganizationCiphersAdminError> {
    let api = api_client.ciphers_api();
    let response: CipherMiniDetailsResponseModelListResponseModel = api
        .get_organization_ciphers(Some(org_id.into()), Some(include_member_items))
        .await
        .map_err(ApiError::from)?;
    let ciphers = response
        .data
        .into_iter()
        .flatten()
        .map(|model| model.merge_with_cipher(None))
        .collect::<Result<Vec<_>, _>>()?;

    let (list_views, _failures) = key_store.decrypt_list_with_failures(&ciphers);
    Ok(ListOrganizationCiphersResult {
        ciphers,
        list_views,
    })
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CipherAdminClient {
    pub async fn list_org_ciphers(
        &self,
        org_id: OrganizationId,
        include_member_items: bool,
    ) -> Result<ListOrganizationCiphersResult, GetOrganizationCiphersAdminError> {
        list_org_ciphers(
            org_id,
            include_member_items,
            &self.client.internal.get_api_configurations().api_client,
            self.client.internal.get_key_store(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{CipherMiniDetailsResponseModel, CipherMiniDetailsResponseModelListResponseModel},
    };
    use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey};
    use chrono::Utc;

    use super::*;
    use crate::{Cipher, CipherType, Login};

    const TEST_ORG_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";
    const TEST_CIPHER_ID_1: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_CIPHER_ID_2: &str = "6faa9684-c793-4a2d-8a12-b33900187098";

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

    fn mock_api_response(cipher: &Cipher) -> CipherMiniDetailsResponseModel {
        CipherMiniDetailsResponseModel {
            id: cipher.id.map(|id| id.into()),
            name: Some(cipher.name.to_string()),
            r#type: Some(cipher.r#type.into()),
            login: cipher.login.clone().map(|l| Box::new(l.into())),
            creation_date: Some(Utc::now().to_rfc3339()),
            revision_date: Some(Utc::now().to_rfc3339()),
            ..Default::default()
        }
    }

    fn setup_key_store() -> KeyStore<KeyIds> {
        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );
        store
    }

    #[tokio::test]
    async fn test_list_org_ciphers_all_success() {
        let cipher_1 = generate_test_cipher();
        let mut cipher_2 = generate_test_cipher();
        cipher_2.id = TEST_CIPHER_ID_2.parse().ok();

        let response_1 = mock_api_response(&cipher_1);
        let response_2 = mock_api_response(&cipher_2);

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_get_organization_ciphers()
                .returning(move |_org_id, _include_member_items| {
                    Ok(CipherMiniDetailsResponseModelListResponseModel {
                        object: None,
                        data: Some(vec![response_1.clone(), response_2.clone()]),
                        continuation_token: None,
                    })
                });
        });

        let store = setup_key_store();
        let result = list_org_ciphers(TEST_ORG_ID.parse().unwrap(), true, &api_client, &store)
            .await
            .unwrap();

        assert_eq!(result.ciphers.len(), 2);
        assert_eq!(result.list_views.len(), 2);
        assert_eq!(result.ciphers[0].id, TEST_CIPHER_ID_1.parse().ok());
        assert_eq!(result.ciphers[1].id, TEST_CIPHER_ID_2.parse().ok());
    }

    #[tokio::test]
    async fn test_list_org_ciphers_with_failures() {
        let cipher = generate_test_cipher();
        let mut cipher_with_bad_key = generate_test_cipher();
        cipher_with_bad_key.id = TEST_CIPHER_ID_2.parse().ok();

        let response_good = mock_api_response(&cipher);
        let mut response_bad = mock_api_response(&cipher_with_bad_key);
        // Set an invalid key to cause decryption failure
        response_bad.key = Some("2.Gg8yCM4IIgykCZyq0O4+cA==|GJLBtfvSJTDJh/F7X4cJPkzI6ccnzJm5DYl3yxOW2iUn7DgkkmzoOe61sUhC5dgVdV0kFqsZPcQ0yehlN1DDsFIFtrb4x7LwzJNIkMgxNyg=|1rGkGJ8zcM5o5D0aIIwAyLsjMLrPsP3EWm3CctBO3Fw=".to_string());

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_get_organization_ciphers()
                .returning(move |_org_id, _include_member_items| {
                    Ok(CipherMiniDetailsResponseModelListResponseModel {
                        object: None,
                        data: Some(vec![response_good.clone(), response_bad.clone()]),
                        continuation_token: None,
                    })
                });
        });

        let store = setup_key_store();
        let result = list_org_ciphers(TEST_ORG_ID.parse().unwrap(), true, &api_client, &store)
            .await
            .unwrap();

        // All ciphers should be returned (both good and bad)
        assert_eq!(result.ciphers.len(), 2);
        // Only the good cipher should decrypt successfully
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

        let store = setup_key_store();
        let result = list_org_ciphers(TEST_ORG_ID.parse().unwrap(), false, &api_client, &store)
            .await
            .unwrap();

        assert!(result.ciphers.is_empty());
        assert!(result.list_views.is_empty());
    }
}
