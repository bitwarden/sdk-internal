use std::collections::HashMap;

use bitwarden_api_api::{apis::ciphers_api, models::CipherRequestModel};
use bitwarden_core::{
    key_management::{KeyIds, SymmetricKeyId},
    ApiError, MissingFieldError, UserId,
};
use bitwarden_crypto::{CompositeEncryptable, CryptoError, IdentifyKey, KeyStore, KeyStoreContext};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::CiphersClient;
use crate::{
    password_history::PasswordChange, Cipher, CipherId, CipherType, CipherView, FieldType,
    FieldView, ItemNotFoundError, PasswordHistoryView, VaultParseError,
};

/// Maximum number of password history entries to retain
const MAX_PASSWORD_HISTORY_ENTRIES: usize = 5;

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

/// Request to edit a cipher.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CipherEditRequest {
    /// The cipher view data to be added or edited.
    pub cipher: CipherView,
    /// The user ID for whom this cipher is encrypted (internal use only).
    pub encrypted_for: Option<UserId>,
}

impl CipherEditRequest {
    pub fn update_password_history(&mut self, original_cipher: &CipherView) {
        let mut history = original_cipher.password_history.clone().unwrap_or_default();

        let mut changes = Vec::new();

        if let Some(login_changes) = self.detect_login_password_changes(original_cipher) {
            changes.extend(login_changes);
        }

        changes.extend(self.detect_hidden_field_changes(original_cipher));

        for change in changes.into_iter().rev() {
            history.insert(0, change.into_history_entry());
        }

        Self::limit_history_length(&mut history);

        self.cipher.password_history = (!history.is_empty()).then_some(history);
    }

    fn detect_login_password_changes(
        &mut self,
        original_cipher: &CipherView,
    ) -> Option<Vec<PasswordChange>> {
        if self.cipher.r#type != CipherType::Login || original_cipher.r#type != CipherType::Login {
            return None;
        }

        let original_login = original_cipher.login.as_ref()?;
        let current_login = self.cipher.login.as_mut()?;

        let original_password = original_login.password.as_deref().unwrap_or("");
        let current_password = current_login.password.as_deref().unwrap_or("");

        if original_password.is_empty() {
            // No original password - set revision date only if adding new password
            if !current_password.is_empty() {
                current_login.password_revision_date = Some(Utc::now());
            }
            None
        } else if original_password == current_password {
            // Password unchanged - preserve original revision date
            current_login.password_revision_date = original_login.password_revision_date;
            None
        } else {
            // Password changed - update revision date and track change
            current_login.password_revision_date = Some(Utc::now());
            Some(vec![PasswordChange::new_password(original_password)])
        }
    }

    fn detect_hidden_field_changes(&self, original_cipher: &CipherView) -> Vec<PasswordChange> {
        let original_fields = Self::extract_hidden_fields(&original_cipher.fields);
        let current_fields = Self::extract_hidden_fields(&self.cipher.fields);

        original_fields
            .into_iter()
            .filter_map(|(field_name, original_value)| {
                let current_value = current_fields.get(&field_name);
                if current_value != Some(&original_value) {
                    Some(PasswordChange::new_field(&field_name, &original_value))
                } else {
                    None
                }
            })
            .collect()
    }

    fn extract_hidden_fields(fields: &Option<Vec<FieldView>>) -> HashMap<String, String> {
        fields
            .as_ref()
            .map(|field_vec| {
                field_vec
                    .iter()
                    .filter_map(|f| match (&f.r#type, &f.name, &f.value) {
                        (FieldType::Hidden, Some(name), Some(value))
                            if !name.is_empty() && !value.is_empty() =>
                        {
                            Some((name.clone(), value.clone()))
                        }
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn limit_history_length(history: &mut Vec<PasswordHistoryView>) {
        if history.len() > MAX_PASSWORD_HISTORY_ENTRIES {
            history.truncate(MAX_PASSWORD_HISTORY_ENTRIES);
        }
    }
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, CipherRequestModel> for CipherEditRequest {
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

impl IdentifyKey<SymmetricKeyId> for CipherEditRequest {
    fn key_identifier(&self) -> SymmetricKeyId {
        self.cipher.key_identifier()
    }
}

async fn edit_cipher<R: Repository<Cipher> + ?Sized>(
    key_store: &KeyStore<KeyIds>,
    api_config: &bitwarden_api_api::apis::configuration::Configuration,
    repository: &R,
    cipher_id: CipherId,
    mut request: CipherEditRequest,
) -> Result<CipherView, EditCipherError> {
    let id = cipher_id.to_string();
    repository.get(id.clone()).await?.ok_or(ItemNotFoundError)?;

    let original_cipher = repository.get(id.clone()).await?.ok_or(ItemNotFoundError)?;
    let original_cipher_view: CipherView = key_store.decrypt(&original_cipher)?;

    // Update password history
    request.update_password_history(&original_cipher_view);

    let cipher_request = key_store.encrypt(request)?;

    let parsed_cipher_id = uuid::Uuid::parse_str(&id)?;
    let response = ciphers_api::ciphers_put(api_config, parsed_cipher_id, Some(cipher_request))
        .await
        .map_err(ApiError::from)?;

    let cipher: Cipher = response.try_into()?;

    debug_assert!(cipher.id.unwrap_or_default() == cipher_id);

    repository
        .set(cipher_id.to_string(), cipher.clone())
        .await?;

    Ok(key_store.decrypt(&cipher)?)
}

impl CiphersClient {
    /// Edit an existing [Cipher] and save it to the server.
    pub async fn edit(
        &self,
        cipher_id: CipherId,
        mut request: CipherEditRequest,
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

    fn create_test_login_cipher(password: &str) -> CipherView {
        let mut cipher_view = generate_test_cipher();
        if let Some(ref mut login) = cipher_view.login {
            login.password = Some(password.to_string());
        }
        cipher_view
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

        let request = CipherEditRequest {
            cipher: cipher_view.clone(),
            encrypted_for: Some(user_id),
        };

        let result = edit_cipher(&store, &api_config, &repository, cipher_id, request)
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

        let request = CipherEditRequest {
            cipher: cipher_view.clone(),
            encrypted_for: None,
        };

        let result = edit_cipher(
            &store,
            &Configuration::default(),
            &repository,
            cipher_id,
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

        let request = CipherEditRequest {
            cipher: cipher_view.clone(),
            encrypted_for: None,
        };

        let result = edit_cipher(&store, &api_config, &repository, cipher_id, request).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EditCipherError::Api(_)));
    }

    #[test]
    fn test_password_history_on_password_change() {
        let original_cipher = create_test_login_cipher("old_password");
        let mut edit_request = CipherEditRequest {
            cipher: create_test_login_cipher("new_password"),
            encrypted_for: None,
        };

        edit_request.update_password_history(&original_cipher);

        let history = edit_request.cipher.password_history.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].password, "old_password");
    }

    #[test]
    fn test_password_history_on_unchanged_password() {
        let original_cipher = create_test_login_cipher("same_password");
        let mut edit_request = CipherEditRequest {
            cipher: create_test_login_cipher("same_password"),
            encrypted_for: None,
        };

        edit_request.update_password_history(&original_cipher);

        assert!(edit_request.cipher.password_history.is_none());
    }

    #[test]
    fn test_password_history_with_hidden_fields() {
        let mut original_cipher = create_test_login_cipher("password");
        original_cipher.fields = Some(vec![FieldView {
            name: Some("Secret Key".to_string()),
            value: Some("old_secret_value".to_string()),
            r#type: FieldType::Hidden,
            linked_id: None,
        }]);

        let mut new_cipher = create_test_login_cipher("password");
        new_cipher.fields = Some(vec![FieldView {
            name: Some("Secret Key".to_string()),
            value: Some("new_secret_value".to_string()),
            r#type: FieldType::Hidden,
            linked_id: None,
        }]);

        let mut edit_request = CipherEditRequest {
            cipher: new_cipher,
            encrypted_for: None,
        };

        edit_request.update_password_history(&original_cipher);

        let history = edit_request.cipher.password_history.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].password, "Secret Key: old_secret_value");
    }

    #[test]
    fn test_password_history_length_limit() {
        let mut original_cipher = create_test_login_cipher("password");
        original_cipher.password_history = Some(
            (0..10)
                .map(|i| PasswordHistoryView {
                    password: format!("old_password_{}", i),
                    last_used_date: Utc::now(),
                })
                .collect(),
        );

        // Create edit request with new password (no existing history)
        let mut edit_request = CipherEditRequest {
            cipher: create_test_login_cipher("new_password"),
            encrypted_for: None,
        };

        edit_request.update_password_history(&original_cipher);

        let history = edit_request.cipher.password_history.unwrap();
        assert_eq!(history.len(), MAX_PASSWORD_HISTORY_ENTRIES);
        // Most recent change (original password) should be first
        assert_eq!(history[0].password, "password");

        assert_eq!(history[1].password, "old_password_0");
        assert_eq!(history[2].password, "old_password_1");
        assert_eq!(history[3].password, "old_password_2");
        assert_eq!(history[4].password, "old_password_3");
    }
}
