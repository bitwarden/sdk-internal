use bitwarden_api_api::{apis::ApiClient, models::CipherCollectionsRequestModel};
use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{
    ApiError, MissingFieldError, NotAuthenticatedError, UserId, key_management::KeyIds,
};
use bitwarden_crypto::{CryptoError, IdentifyKey, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::RepositoryError;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::CipherAdminClient;
use crate::{
    Cipher, CipherId, CipherView, DecryptError, ItemNotFoundError, VaultParseError,
    cipher::cipher::PartialCipher,
    cipher_client::edit::{CipherEditRequest, CipherEditRequestInternal},
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EditCipherAdminError {
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
    NotAuthenticated(#[from] NotAuthenticatedError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    Uuid(#[from] uuid::Error),
    #[error(transparent)]
    Decrypt(#[from] DecryptError),
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for EditCipherAdminError {
    fn from(val: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(val.into())
    }
}

async fn edit_cipher(
    key_store: &KeyStore<KeyIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    encrypted_for: UserId,
    original_cipher_view: CipherView,
    request: CipherEditRequest,
) -> Result<CipherView, EditCipherAdminError> {
    let cipher_id = request.id;
    let request = CipherEditRequestInternal::new(request, &original_cipher_view);

    let mut cipher_request = key_store.encrypt(request)?;
    cipher_request.encrypted_for = Some(encrypted_for.into());

    let orig_cipher = key_store.encrypt(original_cipher_view)?;

    let cipher: Cipher = api_client
        .ciphers_api()
        .put_admin(cipher_id.into(), Some(cipher_request))
        .await
        .map_err(ApiError::from)?
        .merge_with_cipher(Some(orig_cipher))?;

    Ok(key_store.decrypt(&cipher)?)
}

/// Adds the cipher matched by [CipherId] to any number of collections on the server.
pub async fn add_to_collections(
    cipher_id: CipherId,
    collection_ids: Vec<CollectionId>,
    api_client: &ApiClient,
    key_store: &KeyStore<KeyIds>,
) -> Result<CipherView, EditCipherAdminError> {
    let req = CipherCollectionsRequestModel {
        collection_ids: collection_ids
            .into_iter()
            .map(|id| id.to_string())
            .collect(),
    };

    let api = api_client.ciphers_api();
    let cipher: Cipher = api
        .put_collections_admin(&cipher_id.to_string(), Some(req))
        .await?
        .merge_with_cipher(None)?;

    Ok(key_store.decrypt(&cipher)?)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CipherAdminClient {
    /// Edit an existing [Cipher] and save it to the server.
    pub async fn edit(
        &self,
        mut request: CipherEditRequest,
        original_cipher_view: CipherView,
    ) -> Result<CipherView, EditCipherAdminError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations().await;

        let user_id = self
            .client
            .internal
            .get_user_id()
            .ok_or(NotAuthenticatedError)?;

        // TODO: Once this flag is removed, the key generation logic should
        // be moved closer to the actual encryption logic.
        if request.key.is_none()
            && self
                .client
                .internal
                .get_flags()
                .enable_cipher_key_encryption
        {
            let key = request.key_identifier();
            request.generate_cipher_key(&mut key_store.context(), key)?;
        }

        edit_cipher(
            key_store,
            &config.api_client,
            user_id,
            original_cipher_view,
            request,
        )
        .await
    }

    /// Adds the cipher matched by [CipherId] to any number of collections on the server.
    pub async fn update_collection(
        &self,
        cipher_id: CipherId,
        collection_ids: Vec<CollectionId>,
    ) -> Result<CipherView, EditCipherAdminError> {
        add_to_collections(
            cipher_id,
            collection_ids,
            &self
                .client
                .internal
                .get_api_configurations()
                .await
                .api_client,
            self.client.internal.get_key_store(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::CipherMiniResponseModel};
    use bitwarden_core::key_management::SymmetricKeyId;
    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey};

    use super::*;
    use crate::{CipherId, CipherRepromptType, CipherType, LoginView};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_USER_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn generate_test_cipher() -> CipherView {
        CipherView {
            id: Some(TEST_CIPHER_ID.parse().unwrap()),
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

    #[tokio::test]
    async fn test_edit_cipher() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_put_admin()
                .returning(move |_id, body| {
                    let body = body.unwrap();
                    Ok(CipherMiniResponseModel {
                        object: Some("cipher".to_string()),
                        id: Some(cipher_id.into()),
                        name: Some(body.name),
                        r#type: body.r#type,
                        organization_id: body
                            .organization_id
                            .as_ref()
                            .and_then(|id| uuid::Uuid::parse_str(id).ok()),
                        reprompt: body.reprompt,
                        key: body.key,
                        notes: body.notes,
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
                        data: None,
                        archived_date: None,
                    })
                })
                .once();
        });

        let original_cipher_view = generate_test_cipher();
        let mut cipher_view = original_cipher_view.clone();
        cipher_view.name = "New Cipher Name".to_string();

        let request: CipherEditRequest = cipher_view.try_into().unwrap();

        let result = edit_cipher(
            &store,
            &api_client,
            TEST_USER_ID.parse().unwrap(),
            original_cipher_view,
            request,
        )
        .await
        .unwrap();

        assert_eq!(result.id, Some(cipher_id));
        assert_eq!(result.name, "New Cipher Name");
    }

    #[tokio::test]
    async fn test_edit_cipher_http_error() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_put_admin()
                .returning(move |_id, _body| {
                    Err(bitwarden_api_api::apis::Error::Io(std::io::Error::other(
                        "Simulated error",
                    )))
                });
        });
        let orig_cipher_view = generate_test_cipher();
        let cipher_view = orig_cipher_view.clone();
        let request: CipherEditRequest = cipher_view.try_into().unwrap();
        let result = edit_cipher(
            &store,
            &api_client,
            TEST_USER_ID.parse().unwrap(),
            orig_cipher_view,
            request,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EditCipherAdminError::Api(_)));
    }
}
