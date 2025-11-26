use bitwarden_api_api::models::{CipherBulkDeleteRequestModel, CipherBulkRestoreRequestModel};
use bitwarden_core::{ApiError, OrganizationId};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::RepositoryError;
use chrono::Utc;
use thiserror::Error;

use crate::{
    Cipher, CipherId, CipherView, CiphersClient, DecryptCipherListResult, DecryptError,
    VaultParseError,
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
    Decrypt(#[from] DecryptError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for RestoreCipherError {
    fn from(val: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(val.into())
    }
}

impl CiphersClient {
    /// Restores a soft-deleted cipher on the server.
    pub async fn restore(&self, cipher_id: CipherId) -> Result<CipherView, RestoreCipherError> {
        let api_config = self.get_api_configurations().await;
        let api = api_config.api_client.ciphers_api();

        let cipher: Cipher = api.put_restore(cipher_id.into()).await?.try_into()?;
        self.get_repository()?
            .set(cipher_id.to_string(), cipher.clone())
            .await?;

        Ok(self.decrypt(cipher)?)
    }

    /// Restores a soft-deleted cipher on the server, using the admin endpoint.
    pub async fn restore_as_admin(
        &self,
        cipher_id: CipherId,
    ) -> Result<CipherView, RestoreCipherError> {
        let api_config = self.get_api_configurations().await;
        let api = api_config.api_client.ciphers_api();

        let cipher: Cipher = api.put_restore_admin(cipher_id.into()).await?.try_into()?;

        Ok(self.decrypt(cipher)?)
    }

    /// Restores multiple soft-deleted ciphers on the server.
    pub async fn restore_many(
        &self,
        cipher_ids: Vec<CipherId>,
    ) -> Result<DecryptCipherListResult, RestoreCipherError> {
        let api_config = self.get_api_configurations().await;
        let api = api_config.api_client.ciphers_api();

        let ciphers: Vec<Cipher> = api
            .put_restore_many(Some(CipherBulkRestoreRequestModel {
                ids: cipher_ids.into_iter().map(|id| id.to_string()).collect(),
                organization_id: None,
            }))
            .await?
            .data
            .into_iter()
            .flatten()
            .map(|c| c.try_into())
            .collect::<Result<Vec<Cipher>, _>>()?;

        for cipher in &ciphers {
            if let Some(id) = &cipher.id {
                self.get_repository()?
                    .set(id.to_string(), cipher.clone())
                    .await?;
            }
        }

        Ok(self.decrypt_list_with_failures(ciphers))
    }

    /// Restores multiple soft-deleted ciphers on the server.
    pub async fn restore_many_as_admin(
        &self,
        cipher_ids: Vec<CipherId>,
        org_id: OrganizationId,
    ) -> Result<DecryptCipherListResult, RestoreCipherError> {
        let api_config = self.get_api_configurations().await;
        let api = api_config.api_client.ciphers_api();

        let ciphers: Vec<Cipher> = api
            .put_restore_many_admin(Some(CipherBulkRestoreRequestModel {
                ids: cipher_ids.into_iter().map(|id| id.to_string()).collect(),
                organization_id: Some(org_id.into()),
            }))
            .await?
            .data
            .into_iter()
            .flatten()
            .map(|c| c.try_into())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self.decrypt_list_with_failures(ciphers))
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::{
        CipherMiniResponseModel, CipherMiniResponseModelListResponseModel, CipherResponseModel,
    };
    use bitwarden_core::{
        Client, ClientSettings, DeviceType, UserId,
        key_management::crypto::{
            InitOrgCryptoRequest, InitUserCryptoMethod, InitUserCryptoRequest,
        },
    };
    use bitwarden_crypto::{EncString, Kdf};
    use bitwarden_test::{MemoryRepository, start_api_mock};

    use chrono::Utc;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path_regex},
    };

    use crate::{Cipher, CipherId, CiphersClient, VaultClientExt};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_CIPHER_ID_2: &str = "6faa9684-c793-4a2d-8a12-b33900187098";
    const TEST_USER_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const TEST_ORG_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";

    async fn create_client_with_wiremock(mock_server: MockServer) -> CiphersClient {
        let settings = ClientSettings {
            identity_url: format!("http://{}", mock_server.address()),
            api_url: format!("http://{}", mock_server.address()),
            user_agent: "Bitwarden Test".into(),
            device_type: DeviceType::SDK,
            bitwarden_client_version: None,
        };

        let client = Client::new(Some(settings));

        client
            .internal
            .load_flags(std::collections::HashMap::from([(
                "enableCipherKeyEncryption".to_owned(),
                true,
            )]));

        let user_request = InitUserCryptoRequest {
            user_id: Some(UserId::new(uuid::uuid!(TEST_USER_ID))),
            kdf_params: Kdf::PBKDF2 {
                iterations: 600_000.try_into().unwrap(),
            },
            email: "test@bitwarden.com".to_owned(),
            private_key: "2.yN7l00BOlUE0Sb0M//Q53w==|EwKG/BduQRQ33Izqc/ogoBROIoI5dmgrxSo82sgzgAMIBt3A2FZ9vPRMY+GWT85JiqytDitGR3TqwnFUBhKUpRRAq4x7rA6A1arHrFp5Tp1p21O3SfjtvB3quiOKbqWk6ZaU1Np9HwqwAecddFcB0YyBEiRX3VwF2pgpAdiPbSMuvo2qIgyob0CUoC/h4Bz1be7Qa7B0Xw9/fMKkB1LpOm925lzqosyMQM62YpMGkjMsbZz0uPopu32fxzDWSPr+kekNNyLt9InGhTpxLmq1go/pXR2uw5dfpXc5yuta7DB0EGBwnQ8Vl5HPdDooqOTD9I1jE0mRyuBpWTTI3FRnu3JUh3rIyGBJhUmHqGZvw2CKdqHCIrQeQkkEYqOeJRJVdBjhv5KGJifqT3BFRwX/YFJIChAQpebNQKXe/0kPivWokHWwXlDB7S7mBZzhaAPidZvnuIhalE2qmTypDwHy22FyqV58T8MGGMchcASDi/QXI6kcdpJzPXSeU9o+NC68QDlOIrMVxKFeE7w7PvVmAaxEo0YwmuAzzKy9QpdlK0aab/xEi8V4iXj4hGepqAvHkXIQd+r3FNeiLfllkb61p6WTjr5urcmDQMR94/wYoilpG5OlybHdbhsYHvIzYoLrC7fzl630gcO6t4nM24vdB6Ymg9BVpEgKRAxSbE62Tqacxqnz9AcmgItb48NiR/He3n3ydGjPYuKk/ihZMgEwAEZvSlNxYONSbYrIGDtOY+8Nbt6KiH3l06wjZW8tcmFeVlWv+tWotnTY9IqlAfvNVTjtsobqtQnvsiDjdEVtNy/s2ci5TH+NdZluca2OVEr91Wayxh70kpM6ib4UGbfdmGgCo74gtKvKSJU0rTHakQ5L9JlaSDD5FamBRyI0qfL43Ad9qOUZ8DaffDCyuaVyuqk7cz9HwmEmvWU3VQ+5t06n/5kRDXttcw8w+3qClEEdGo1KeENcnXCB32dQe3tDTFpuAIMLqwXs6FhpawfZ5kPYvLPczGWaqftIs/RXJ/EltGc0ugw2dmTLpoQhCqrcKEBDoYVk0LDZKsnzitOGdi9mOWse7Se8798ib1UsHFUjGzISEt6upestxOeupSTOh0v4+AjXbDzRUyogHww3V+Bqg71bkcMxtB+WM+pn1XNbVTyl9NR040nhP7KEf6e9ruXAtmrBC2ah5cFEpLIot77VFZ9ilLuitSz+7T8n1yAh1IEG6xxXxninAZIzi2qGbH69O5RSpOJuJTv17zTLJQIIc781JwQ2TTwTGnx5wZLbffhCasowJKd2EVcyMJyhz6ru0PvXWJ4hUdkARJs3Xu8dus9a86N8Xk6aAPzBDqzYb1vyFIfBxP0oO8xFHgd30Cgmz8UrSE3qeWRrF8ftrI6xQnFjHBGWD/JWSvd6YMcQED0aVuQkuNW9ST/DzQThPzRfPUoiL10yAmV7Ytu4fR3x2sF0Yfi87YhHFuCMpV/DsqxmUizyiJuD938eRcH8hzR/VO53Qo3UIsqOLcyXtTv6THjSlTopQ+JOLOnHm1w8dzYbLN44OG44rRsbihMUQp+wUZ6bsI8rrOnm9WErzkbQFbrfAINdoCiNa6cimYIjvvnMTaFWNymqY1vZxGztQiMiHiHYwTfwHTXrb9j0uPM=|09J28iXv9oWzYtzK2LBT6Yht4IT4MijEkk0fwFdrVQ4=".parse::<EncString>().unwrap(),
            signing_key: None,
            security_state: None,
            method: InitUserCryptoMethod::Password {
                password: "asdfasdfasdf".to_owned(),
                user_key: "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=".parse().unwrap(),
            }
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
            .platform()
            .state()
            .register_client_managed(std::sync::Arc::new(MemoryRepository::<Cipher>::default()));

        client.vault().ciphers()
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

        let (mock_server, _config) = start_api_mock(vec![
            Mock::given(method("PUT"))
                .and(path_regex(r"/ciphers/[a-f0-9-]+/restore"))
                .respond_with(move |_req: &wiremock::Request| {
                    ResponseTemplate::new(200).set_body_json(CipherResponseModel {
                        id: Some(TEST_CIPHER_ID.try_into().unwrap()),
                        name: Some(cipher_1.name.to_string()),
                        r#type: Some(cipher_1.r#type.into()),
                        creation_date: Some(cipher_1.creation_date.to_string()),
                        revision_date: Some(Utc::now().to_string()),
                        ..Default::default()
                    })
                }),
        ])
        .await;
        let client = create_client_with_wiremock(mock_server).await;

        let mut cipher = generate_test_cipher();
        cipher.deleted_date = Some(Utc::now());
        let repository = client.get_repository().unwrap();
        repository
            .set(TEST_CIPHER_ID.to_string(), cipher)
            .await
            .unwrap();

        let start_time = Utc::now();
        let updated_cipher = client
            .restore(TEST_CIPHER_ID.parse().unwrap())
            .await
            .unwrap();
        let end_time = Utc::now();
        assert!(updated_cipher.deleted_date.is_none());
        assert!(
            updated_cipher.revision_date >= start_time && updated_cipher.revision_date <= end_time
        );

        let repo_cipher = client
            .get_repository()
            .unwrap()
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
    async fn test_restore_as_admin() {
        let mut cipher = generate_test_cipher();
        cipher.deleted_date = Some(Utc::now());
        let (mock_server, _config) = start_api_mock(vec![
            Mock::given(method("PUT"))
                .and(path_regex(r"/ciphers/[a-f0-9-]+/restore-admin"))
                .respond_with(move |_req: &wiremock::Request| {
                    ResponseTemplate::new(200).set_body_json(CipherResponseModel {
                        id: Some(TEST_CIPHER_ID.try_into().unwrap()),
                        name: Some(cipher.name.to_string()),
                        r#type: Some(cipher.r#type.into()),
                        creation_date: Some(cipher.creation_date.to_string()),
                        revision_date: Some(Utc::now().to_string()),
                        ..Default::default()
                    })
                }),
        ])
        .await;

        let client = create_client_with_wiremock(mock_server).await;

        let start_time = Utc::now();
        let updated_cipher = client
            .restore_as_admin(TEST_CIPHER_ID.parse().unwrap())
            .await
            .unwrap();
        let end_time = Utc::now();

        assert!(updated_cipher.deleted_date.is_none());
        assert!(
            updated_cipher.revision_date >= start_time && updated_cipher.revision_date <= end_time
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

        let (mock_server, _config) = {
            let (cipher_1, cipher_2) = (cipher_1.clone(), cipher_2.clone());
            start_api_mock(vec![
                Mock::given(method("PUT"))
                    .and(path_regex(r"/ciphers/restore"))
                    .respond_with(move |_req: &wiremock::Request| {
                        let (cipher_1, cipher_2) = (cipher_1.clone(), cipher_2.clone());
                        ResponseTemplate::new(200).set_body_json(
                            CipherMiniResponseModelListResponseModel {
                                object: None,
                                data: Some(vec![
                                    CipherMiniResponseModel {
                                        id: cipher_1.id.map(|id| id.into()),
                                        name: Some(cipher_1.name.to_string()),
                                        r#type: Some(cipher_1.r#type.into()),
                                        creation_date: cipher_1.creation_date.to_string().into(),
                                        deleted_date: None,
                                        revision_date: Some(Utc::now().to_string()),
                                        ..Default::default()
                                    },
                                    CipherMiniResponseModel {
                                        id: cipher_2.id.map(|id| id.into()),
                                        name: Some(cipher_2.name.to_string()),
                                        r#type: Some(cipher_2.r#type.into()),
                                        creation_date: cipher_2.creation_date.to_string().into(),
                                        deleted_date: None,
                                        revision_date: Some(Utc::now().to_string()),
                                        ..Default::default()
                                    },
                                ]),
                                continuation_token: None,
                            },
                        )
                    }),
            ])
            .await
        };
        let client = create_client_with_wiremock(mock_server).await;

        let repository = client.get_repository().unwrap();
        repository
            .set(cipher_id.to_string(), cipher_1)
            .await
            .unwrap();
        repository
            .set(TEST_CIPHER_ID_2.to_string(), cipher_2)
            .await
            .unwrap();

        let start_time = Utc::now();
        let ciphers = client
            .restore_many(vec![cipher_id, cipher_id_2])
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

    #[tokio::test]
    async fn test_restore_many_as_admin() {
        let (mock_server, _config) = start_api_mock(vec![
            Mock::given(method("PUT"))
                .and(path_regex(r"/ciphers/restore-admin"))
                .respond_with(move |_req: &wiremock::Request| ResponseTemplate::new(200)),
        ])
        .await;
        let client = create_client_with_wiremock(mock_server).await;

        let ciphers = client
            .restore_many(vec![
                TEST_CIPHER_ID.parse().unwrap(),
                TEST_CIPHER_ID_2.parse().unwrap(),
            ])
            .await
            .unwrap();

        assert_eq!(ciphers.successes.len(), 2,);
        assert_eq!(ciphers.failures.len(), 0,);
        assert_eq!(
            ciphers.successes[0].id,
            Some(TEST_CIPHER_ID.parse().unwrap()),
        );
        assert_eq!(
            ciphers.successes[1].id,
            Some(TEST_CIPHER_ID.parse().unwrap()),
        );
        assert_eq!(ciphers.successes[0].deleted_date, None,);
        assert_eq!(ciphers.successes[1].deleted_date, None,);
    }
}
