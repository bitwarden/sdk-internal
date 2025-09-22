use bitwarden_api_api::{apis::ciphers_api, models::CipherRequestModel};
use bitwarden_core::{
    key_management::{KeyIds, SymmetricKeyId},
    require, ApiError, MissingFieldError, UserId,
};
use bitwarden_crypto::{CompositeEncryptable, CryptoError, IdentifyKey, KeyStoreContext};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::RepositoryError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::CiphersClient;
use crate::{Cipher, CipherView, VaultParseError};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CreateCipherError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Request to add or edit a cipher.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CipherAddEditRequest {
    /// The cipher view data to be added or edited.
    pub cipher: CipherView,
    /// The user ID for whom this cipher is encrypted (internal use only).
    pub encrypted_for: Option<UserId>,
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, CipherRequestModel> for CipherAddEditRequest {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<CipherRequestModel, CryptoError> {
        let encrypted_cipher = self.cipher.encrypt_composite(ctx, key)?;

        let cipher_request = CipherRequestModel {
            encrypted_for: self.encrypted_for.map(|id| id.into()),
            r#type: Some(encrypted_cipher.r#type.into()),
            organization_id: encrypted_cipher.organization_id.map(|id| id.to_string()),
            folder_id: encrypted_cipher.folder_id.map(|id| id.to_string()),
            favorite: Some(encrypted_cipher.favorite),
            reprompt: Some(encrypted_cipher.reprompt.into()),
            key: encrypted_cipher.key.map(|k| k.to_string()),
            name: encrypted_cipher.name.to_string(),
            notes: encrypted_cipher.notes.map(|n| n.to_string()),
            fields: encrypted_cipher
                .fields
                .map(|f| f.into_iter().map(|f| f.into()).collect()),
            password_history: encrypted_cipher
                .password_history
                .map(|ph| ph.into_iter().map(|ph| ph.into()).collect()),
            attachments: None,
            attachments2: encrypted_cipher.attachments.map(|a| {
                a.into_iter()
                    .filter_map(|a| {
                        a.id.map(|id| {
                            (
                                id,
                                bitwarden_api_api::models::CipherAttachmentModel {
                                    file_name: a.file_name.map(|n| n.to_string()),
                                    key: a.key.map(|k| k.to_string()),
                                },
                            )
                        })
                    })
                    .collect()
            }),
            login: encrypted_cipher.login.map(|l| Box::new(l.into())),
            card: encrypted_cipher.card.map(|c| Box::new(c.into())),
            identity: encrypted_cipher.identity.map(|i| Box::new(i.into())),
            secure_note: encrypted_cipher
                .secure_note
                .map(|note| Box::new(note.into())),
            ssh_key: encrypted_cipher.ssh_key.map(|key| Box::new(key.into())),
            last_known_revision_date: Some(encrypted_cipher.revision_date.to_rfc3339()),
            archived_date: None,
        };

        Ok(cipher_request)
    }
}

impl IdentifyKey<SymmetricKeyId> for CipherAddEditRequest {
    fn key_identifier(&self) -> SymmetricKeyId {
        self.cipher.key_identifier()
    }
}

impl CiphersClient {
    /// Create a new [Cipher] and save it to the server.
    pub async fn create(
        &self,
        mut request: CipherAddEditRequest,
    ) -> Result<CipherView, CreateCipherError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations().await;
        let repository = self.get_repository()?;

        request.encrypted_for = self.client.internal.get_user_id();

        let cipher_request = key_store.encrypt(request)?;
        let resp = ciphers_api::ciphers_post(&config.api, Some(cipher_request))
            .await
            .map_err(ApiError::from)?;

        let cipher: Cipher = resp.try_into()?;

        repository
            .set(require!(cipher.id).to_string(), cipher.clone())
            .await?;

        Ok(key_store.decrypt(&cipher)?)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::models::CipherResponseModel;
    use bitwarden_core::{
        client::test_accounts::test_bitwarden_com_account, Client, ClientSettings, DeviceType,
    };
    use bitwarden_state::repository::Repository;
    use bitwarden_test::{start_api_mock, MemoryRepository};
    use wiremock::{matchers, Mock, Request, ResponseTemplate};

    use super::*;
    use crate::{CipherId, CipherRepromptType, CipherType, LoginView, VaultClientExt};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_USER_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn generate_test_cipher() -> CipherView {
        CipherView {
            id: None,
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: "Test Login".to_string(),
            notes: Some("Test notes".to_string()),
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
            creation_date: "2025-01-01T00:00:00Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
            archived_date: None,
        }
    }

    #[tokio::test]
    async fn test_create_cipher() {
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let user_id: UserId = TEST_USER_ID.parse().unwrap();

        let (mock_server, _api_config) =
            start_api_mock(vec![Mock::given(matchers::path("/api/ciphers"))
                .respond_with(move |req: &Request| {
                    let body: CipherRequestModel = req.body_json().unwrap();
                    ResponseTemplate::new(201).set_body_json(CipherResponseModel {
                        object: Some("cipher".to_string()),
                        id: Some(cipher_id.into()),
                        name: Some(body.name.clone()),
                        r#type: body.r#type,
                        organization_id: body
                            .organization_id
                            .as_ref()
                            .and_then(|id| uuid::Uuid::parse_str(id).ok()),
                        folder_id: body
                            .folder_id
                            .as_ref()
                            .and_then(|id| uuid::Uuid::parse_str(id).ok()),
                        favorite: body.favorite,
                        reprompt: body.reprompt,
                        key: body.key.clone(),
                        notes: body.notes.clone(),
                        view_password: Some(true),
                        edit: Some(true),
                        organization_use_totp: Some(true),
                        revision_date: Some("2025-01-01T00:00:00Z".to_string()),
                        creation_date: Some("2025-01-01T00:00:00Z".to_string()),
                        deleted_date: None,
                        login: body.login,
                        card: body.card,
                        identity: body.identity,
                        secure_note: body.secure_note,
                        ssh_key: body.ssh_key,
                        fields: body.fields,
                        password_history: body.password_history,
                        attachments: None,
                        permissions: None,
                        data: None,
                        archived_date: None,
                    })
                })
                .expect(1)])
            .await;

        let settings = ClientSettings {
            identity_url: format!("http://{}/identity", mock_server.address()),
            api_url: format!("http://{}/api", mock_server.address()),
            user_agent: "Bitwarden Rust-SDK [TEST]".into(),
            device_type: DeviceType::SDK,
        };
        let client = Client::init_test_account(test_bitwarden_com_account(), Some(settings)).await;

        let repository = Arc::new(MemoryRepository::<Cipher>::default());
        client
            .platform()
            .state()
            .register_client_managed(repository.clone());

        let cipher_view = generate_test_cipher();

        let request = CipherAddEditRequest {
            cipher: cipher_view.clone(),
            encrypted_for: Some(user_id),
        };

        let result = client.vault().ciphers().create(request).await.unwrap();

        assert_eq!(result.id, Some(cipher_id));
        assert_eq!(result.name, "Test Login");
        assert_eq!(
            result.login,
            Some(LoginView {
                username: Some("test@example.com".to_string()),
                password: Some("password123".to_string()),
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            })
        );

        let key_store = client.internal.get_key_store();
        // Confirm the cipher was stored in the repository
        let stored_cipher_view: CipherView = key_store
            .decrypt(
                &repository
                    .get(cipher_id.to_string())
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();

        assert_eq!(stored_cipher_view.id, result.id);
        assert_eq!(stored_cipher_view.name, result.name);
        assert_eq!(stored_cipher_view.r#type, result.r#type);
        assert!(stored_cipher_view.login.is_some());
        assert_eq!(stored_cipher_view.favorite, result.favorite);
    }

    #[tokio::test]
    async fn test_create_cipher_http_error() {
        let (mock_server, _api_config) =
            start_api_mock(vec![Mock::given(matchers::path("/api/ciphers"))
                .respond_with(ResponseTemplate::new(500))])
            .await;

        let settings = ClientSettings {
            identity_url: format!("http://{}/identity", mock_server.address()),
            api_url: format!("http://{}/api", mock_server.address()),
            user_agent: "Bitwarden Rust-SDK [TEST]".into(),
            device_type: DeviceType::SDK,
        };
        let client = Client::init_test_account(test_bitwarden_com_account(), Some(settings)).await;
        let repository = Arc::new(MemoryRepository::<Cipher>::default());
        client
            .platform()
            .state()
            .register_client_managed(repository.clone());

        let cipher_view = generate_test_cipher();

        let request = CipherAddEditRequest {
            cipher: cipher_view,
            encrypted_for: None,
        };

        let result = client.vault().ciphers().create(request).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CreateCipherError::Api(_)));
    }
}
