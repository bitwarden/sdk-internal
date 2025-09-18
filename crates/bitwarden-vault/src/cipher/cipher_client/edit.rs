use bitwarden_api_api::apis::ciphers_api;
use bitwarden_core::{key_management::KeyIds, ApiError, MissingFieldError};
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;

use super::CiphersClient;
use crate::{
    cipher_client::create::CipherAddEditRequest, Cipher, CipherView, ItemNotFoundError,
    VaultParseError,
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EditCipherError {
    #[error(transparent)]
    ItemNotFound(#[from] ItemNotFoundError),
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
    #[error(transparent)]
    Uuid(#[from] uuid::Error),
}

async fn edit_cipher<R: Repository<Cipher> + ?Sized>(
    key_store: &KeyStore<KeyIds>,
    api_config: &bitwarden_api_api::apis::configuration::Configuration,
    repository: &R,
    cipher_id: &str,
    request: CipherAddEditRequest,
) -> Result<CipherView, EditCipherError> {
    repository
        .get(cipher_id.to_owned())
        .await?
        .ok_or(ItemNotFoundError)?;

    let cipher_request = key_store.encrypt(request)?;

    let parsed_cipher_id = uuid::Uuid::parse_str(cipher_id)?;

    let response = ciphers_api::ciphers_id_put(api_config, parsed_cipher_id, Some(cipher_request))
        .await
        .map_err(ApiError::from)?;

    let cipher: Cipher = response.try_into()?;

    debug_assert!(cipher.id.unwrap_or_default().to_string() == cipher_id);

    repository
        .set(cipher_id.to_string(), cipher.clone())
        .await?;

    Ok(key_store.decrypt(&cipher)?)
}

impl CiphersClient {
    /// Edit an existing [Cipher] and save it to the server.
    pub async fn edit(
        &self,
        cipher_id: &str,
        mut request: CipherAddEditRequest,
    ) -> Result<CipherView, EditCipherError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations().await;
        let repository = self.get_repository()?;

        request.encrypted_for = self.client.internal.get_user_id();

        edit_cipher(
            key_store,
            &config.api,
            repository.as_ref(),
            cipher_id,
            request,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::configuration::Configuration,
        models::{CipherRequestModel, CipherResponseModel},
    };
    use bitwarden_core::{key_management::SymmetricKeyId, UserId};
    use bitwarden_crypto::{KeyStore, PrimitiveEncryptable, SymmetricCryptoKey};
    use bitwarden_test::{start_api_mock, MemoryRepository};
    use wiremock::{matchers, Mock, Request, ResponseTemplate};

    use super::*;
    use crate::{Cipher, CipherId, CipherRepromptType, CipherType, Login, LoginView};

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
            notes: None,
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

    async fn repository_add_cipher(
        repository: &MemoryRepository<Cipher>,
        store: &KeyStore<KeyIds>,
        cipher_id: CipherId,
        name: &str,
    ) {
        let mut ctx = store.context();

        repository
            .set(
                cipher_id.to_string(),
                Cipher {
                    id: Some(cipher_id),
                    organization_id: None,
                    folder_id: None,
                    collection_ids: vec![],
                    key: None,
                    name: name.encrypt(&mut ctx, SymmetricKeyId::User).unwrap(),
                    notes: None,
                    r#type: CipherType::Login,
                    login: Some(Login {
                        username: Some("test@example.com")
                            .map(|u| u.encrypt(&mut ctx, SymmetricKeyId::User))
                            .transpose()
                            .unwrap(),
                        password: Some("password123")
                            .map(|p| p.encrypt(&mut ctx, SymmetricKeyId::User))
                            .transpose()
                            .unwrap(),
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
                    creation_date: "2024-01-01T00:00:00Z".parse().unwrap(),
                    deleted_date: None,
                    revision_date: "2024-01-01T00:00:00Z".parse().unwrap(),
                    archived_date: None,
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_edit_cipher() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let user_id: UserId = TEST_USER_ID.parse().unwrap();

        let (_server, api_config) = start_api_mock(vec![Mock::given(matchers::path(format!(
            "/ciphers/{}",
            cipher_id
        )))
        .respond_with(move |req: &Request| {
            let body: CipherRequestModel = req.body_json().unwrap();
            ResponseTemplate::new(200).set_body_json(CipherResponseModel {
                object: Some("cipher".to_string()),
                id: Some(cipher_id.into()),
                name: Some(body.name),
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
                key: body.key,
                notes: body.notes,
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

        let repository = MemoryRepository::<Cipher>::default();
        repository_add_cipher(&repository, &store, cipher_id, "old_name").await;
        let cipher_view = generate_test_cipher();

        let request = CipherAddEditRequest {
            cipher: cipher_view.clone(),
            encrypted_for: Some(user_id),
        };

        let result = edit_cipher(
            &store,
            &api_config,
            &repository,
            &cipher_id.to_string(),
            request,
        )
        .await
        .unwrap();

        assert_eq!(result.id, Some(cipher_id));
        assert_eq!(result.name, "Test Login");
    }

    #[tokio::test]
    async fn test_edit_cipher_does_not_exist() {
        let store: KeyStore<KeyIds> = KeyStore::default();

        let repository = MemoryRepository::<Cipher>::default();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let cipher_view = generate_test_cipher();

        let request = CipherAddEditRequest {
            cipher: cipher_view.clone(),
            encrypted_for: None,
        };

        let result = edit_cipher(
            &store,
            &Configuration::default(),
            &repository,
            &cipher_id.to_string(),
            request,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EditCipherError::ItemNotFound(_)
        ));
    }

    #[tokio::test]
    async fn test_edit_cipher_http_error() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let cipher_id: CipherId = "5faa9684-c793-4a2d-8a12-b33900187097".parse().unwrap();

        let (_server, api_config) = start_api_mock(vec![Mock::given(matchers::path(format!(
            "/ciphers/{}",
            cipher_id
        )))
        .respond_with(ResponseTemplate::new(500))])
        .await;

        let repository = MemoryRepository::<Cipher>::default();
        repository_add_cipher(&repository, &store, cipher_id, "old_name").await;
        let cipher_view = generate_test_cipher();

        let request = CipherAddEditRequest {
            cipher: cipher_view.clone(),
            encrypted_for: None,
        };

        let result = edit_cipher(
            &store,
            &api_config,
            &repository,
            &cipher_id.to_string(),
            request,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EditCipherError::Api(_)));
    }
}
