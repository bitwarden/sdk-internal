use bitwarden_api_api::models::{CipherCollectionsRequestModel, CipherRequestModel};
use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{
    ApiError, MissingFieldError, NotAuthenticatedError, OrganizationId, UserId,
    key_management::{KeyIds, SymmetricKeyId},
    require,
};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, EncString, IdentifyKey, KeyStore, KeyStoreContext,
    PrimitiveEncryptable,
};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::CiphersClient;
use crate::{
    AttachmentView, Cipher, CipherId, CipherRepromptType, CipherType, CipherView, DecryptError,
    FieldView, FolderId, ItemNotFoundError, PasswordHistoryView, VaultParseError,
    cipher_view_type::CipherViewType, password_history::MAX_PASSWORD_HISTORY_ENTRIES,
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
    NotAuthenticated(#[from] NotAuthenticatedError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    Uuid(#[from] uuid::Error),
    #[error(transparent)]
    Decrypt(#[from] DecryptError),
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for EditCipherError {
    fn from(val: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(val.into())
    }
}

/// Request to edit a cipher.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CipherEditRequest {
    pub id: CipherId,

    pub organization_id: Option<OrganizationId>,
    pub folder_id: Option<FolderId>,
    pub favorite: bool,
    pub reprompt: CipherRepromptType,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Vec<FieldView>,
    pub r#type: CipherViewType,
    pub revision_date: DateTime<Utc>,
    pub archived_date: Option<DateTime<Utc>>,
    pub attachments: Vec<AttachmentView>,
    pub key: Option<EncString>,
}

impl TryFrom<CipherView> for CipherEditRequest {
    type Error = MissingFieldError;

    fn try_from(value: CipherView) -> Result<Self, Self::Error> {
        let type_data = match value.r#type {
            CipherType::Login => value.login.map(CipherViewType::Login),
            CipherType::SecureNote => value.secure_note.map(CipherViewType::SecureNote),
            CipherType::Card => value.card.map(CipherViewType::Card),
            CipherType::Identity => value.identity.map(CipherViewType::Identity),
            CipherType::SshKey => value.ssh_key.map(CipherViewType::SshKey),
        };
        Ok(Self {
            id: value.id.ok_or(MissingFieldError("id"))?,
            organization_id: value.organization_id,
            folder_id: value.folder_id,
            favorite: value.favorite,
            reprompt: value.reprompt,
            key: value.key,
            name: value.name,
            notes: value.notes,
            fields: value.fields.unwrap_or_default(),
            r#type: require!(type_data),
            attachments: value.attachments.unwrap_or_default(),
            revision_date: value.revision_date,
            archived_date: value.archived_date,
        })
    }
}

impl CipherEditRequest {
    pub(crate) fn generate_cipher_key(
        &mut self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<(), CryptoError> {
        let old_key = Cipher::decrypt_cipher_key(ctx, key, &self.key)?;

        let new_key = ctx.generate_symmetric_key();

        // Re-encrypt the internal fields with the new key
        self.r#type
            .as_login_view_mut()
            .map(|l| l.reencrypt_fido2_credentials(ctx, old_key, new_key))
            .transpose()?;
        AttachmentView::reencrypt_keys(&mut self.attachments, ctx, old_key, new_key)?;
        Ok(())
    }
}

/// Used as an intermediary between the public-facing [CipherEditRequest], and the encrypted
/// value. This allows us to calculate password history safely, without risking misuse.
#[derive(Clone, Debug)]

struct CipherEditRequestInternal {
    edit_request: CipherEditRequest,
    password_history: Vec<PasswordHistoryView>,
}

impl CipherEditRequestInternal {
    fn new(edit_request: CipherEditRequest, orig_cipher: &CipherView) -> Self {
        let mut internal_req = Self {
            edit_request,
            password_history: vec![],
        };
        internal_req.update_password_history(orig_cipher);

        internal_req
    }

    fn update_password_history(&mut self, original_cipher: &CipherView) {
        let changes = self
            .detect_login_password_changes(original_cipher)
            .into_iter()
            .chain(self.detect_hidden_field_changes(original_cipher));
        let history: Vec<_> = changes
            .rev()
            .chain(original_cipher.password_history.iter().flatten().cloned())
            .take(MAX_PASSWORD_HISTORY_ENTRIES)
            .collect();

        self.password_history = history;
    }

    fn detect_login_password_changes(
        &mut self,
        original_cipher: &CipherView,
    ) -> Vec<PasswordHistoryView> {
        self.edit_request
            .r#type
            .as_login_view_mut()
            .map_or(vec![], |login| {
                login.detect_password_change(&original_cipher.login)
            })
    }

    fn detect_hidden_field_changes(
        &self,
        original_cipher: &CipherView,
    ) -> Vec<PasswordHistoryView> {
        FieldView::detect_hidden_field_changes(
            self.edit_request.fields.as_slice(),
            original_cipher.fields.as_deref().unwrap_or(&[]),
        )
    }

    fn generate_checksums(&mut self) {
        if let Some(login) = &mut self.edit_request.r#type.as_login_view_mut() {
            login.generate_checksums();
        }
    }
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, CipherRequestModel>
    for CipherEditRequestInternal
{
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<CipherRequestModel, CryptoError> {
        let mut cipher_data = (*self).clone();
        cipher_data.generate_checksums();

        let cipher_key = Cipher::decrypt_cipher_key(ctx, key, &self.edit_request.key)?;

        let cipher_request = CipherRequestModel {
            encrypted_for: None,
            r#type: Some(cipher_data.edit_request.r#type.get_cipher_type().into()),
            organization_id: cipher_data
                .edit_request
                .organization_id
                .map(|id| id.to_string()),
            folder_id: cipher_data.edit_request.folder_id.map(|id| id.to_string()),
            favorite: Some(cipher_data.edit_request.favorite),
            reprompt: Some(cipher_data.edit_request.reprompt.into()),
            key: cipher_data.edit_request.key.map(|k| k.to_string()),
            name: cipher_data
                .edit_request
                .name
                .encrypt(ctx, cipher_key)?
                .to_string(),
            notes: cipher_data
                .edit_request
                .notes
                .as_ref()
                .map(|n| n.encrypt(ctx, cipher_key))
                .transpose()?
                .map(|n| n.to_string()),
            fields: Some(
                cipher_data
                    .edit_request
                    .fields
                    .encrypt_composite(ctx, cipher_key)?
                    .into_iter()
                    .map(|f| f.into())
                    .collect(),
            ),
            password_history: Some(
                cipher_data
                    .password_history
                    .encrypt_composite(ctx, cipher_key)?
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            ),
            attachments: None,
            attachments2: Some(
                cipher_data
                    .edit_request
                    .attachments
                    .encrypt_composite(ctx, cipher_key)?
                    .into_iter()
                    .map(|a| {
                        Ok((
                            a.id.clone().ok_or(CryptoError::MissingField("id"))?,
                            a.into(),
                        )) as Result<_, CryptoError>
                    })
                    .collect::<Result<_, _>>()?,
            ),
            login: cipher_data
                .edit_request
                .r#type
                .as_login_view()
                .map(|l| l.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|l| Box::new(l.into())),
            card: cipher_data
                .edit_request
                .r#type
                .as_card_view()
                .map(|c| c.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|c| Box::new(c.into())),
            identity: cipher_data
                .edit_request
                .r#type
                .as_identity_view()
                .map(|i| i.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|c| Box::new(c.into())),

            secure_note: cipher_data
                .edit_request
                .r#type
                .as_secure_note_view()
                .map(|i| i.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|c| Box::new(c.into())),
            ssh_key: cipher_data
                .edit_request
                .r#type
                .as_ssh_key_view()
                .map(|i| i.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|c| Box::new(c.into())),

            last_known_revision_date: Some(cipher_data.edit_request.revision_date.to_rfc3339()),
            archived_date: cipher_data
                .edit_request
                .archived_date
                .map(|d| d.to_rfc3339()),
            data: None,
        };

        Ok(cipher_request)
    }
}

impl IdentifyKey<SymmetricKeyId> for CipherEditRequest {
    fn key_identifier(&self) -> SymmetricKeyId {
        match self.organization_id {
            Some(organization_id) => SymmetricKeyId::Organization(organization_id),
            None => SymmetricKeyId::User,
        }
    }
}

impl IdentifyKey<SymmetricKeyId> for CipherEditRequestInternal {
    fn key_identifier(&self) -> SymmetricKeyId {
        self.edit_request.key_identifier()
    }
}

async fn edit_cipher<R: Repository<Cipher> + ?Sized>(
    key_store: &KeyStore<KeyIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    encrypted_for: UserId,
    request: CipherEditRequest,
    is_admin: bool,
) -> Result<CipherView, EditCipherError> {
    let cipher_id = request.id;

    let original_cipher = repository
        .get(cipher_id.to_string())
        .await?
        .ok_or(ItemNotFoundError)?;
    let original_cipher_view: CipherView = key_store.decrypt(&original_cipher)?;

    let request = CipherEditRequestInternal::new(request, &original_cipher_view);

    let mut cipher_request = key_store.encrypt(request)?;
    cipher_request.encrypted_for = Some(encrypted_for.into());

    let cipher = if is_admin {
        api_client
            .ciphers_api()
            .put_admin(cipher_id.into(), Some(cipher_request))
            .await
            .map_err(ApiError::from)?
            .try_into()?
    } else {
        let cipher: Cipher = api_client
            .ciphers_api()
            .put(cipher_id.into(), Some(cipher_request))
            .await
            .map_err(ApiError::from)?
            .try_into()?;

        debug_assert!(cipher.id.unwrap_or_default() == cipher_id);

        repository
            .set(cipher_id.to_string(), cipher.clone())
            .await?;
        cipher
    };

    Ok(key_store.decrypt(&cipher)?)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    /// Edit an existing [Cipher] and save it to the server.
    pub async fn edit(&self, request: CipherEditRequest) -> Result<CipherView, EditCipherError> {
        self.edit_internal(request, false).await
    }

    // putCipherAdmin(id, request: CipherRequest)
    // ciphers_id_admin_put
    #[allow(missing_docs)] // TODO: add docs
    pub async fn edit_as_admin(
        &self,
        request: CipherEditRequest,
    ) -> Result<CipherView, EditCipherError> {
        self.edit_internal(request, true).await
    }

    async fn edit_internal(
        &self,
        mut request: CipherEditRequest,
        is_admin: bool,
    ) -> Result<CipherView, EditCipherError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations().await;
        let repository = self.get_repository()?;

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
            repository.as_ref(),
            user_id,
            request,
            is_admin,
        )
        .await
    }

    /// Adds the cipher matched by [CipherId] to any number of collections on the server.
    pub async fn update_collection(
        &self,
        cipher_id: CipherId,
        collection_ids: Vec<CollectionId>,
        is_admin: bool,
    ) -> Result<CipherView, EditCipherError> {
        let req = CipherCollectionsRequestModel {
            collection_ids: collection_ids
                .into_iter()
                .map(|id| id.to_string())
                .collect(),
        };

        let api_config = self.get_api_configurations().await;
        let api = api_config.api_client.ciphers_api();
        let cipher = if is_admin {
            api.put_collections_admin(&cipher_id.to_string(), Some(req))
                .await?
                .try_into()?
        } else {
            let response: Cipher = api
                .put_collections(cipher_id.into(), Some(req))
                .await?
                .try_into()?;
            self.get_repository()?
                .set(cipher_id.to_string(), response.clone())
                .await?;
            response
        };

        Ok(self.decrypt(cipher)?)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::CipherResponseModel};
    use bitwarden_core::{
        Client, ClientSettings, DeviceType,
        key_management::{
            SymmetricKeyId,
            crypto::{InitOrgCryptoRequest, InitUserCryptoMethod, InitUserCryptoRequest},
        },
    };
    use bitwarden_crypto::{Kdf, KeyStore, PrimitiveEncryptable, SymmetricCryptoKey};
    use bitwarden_test::{MemoryRepository, start_api_mock};
    use chrono::TimeZone;
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path_regex},
    };

    use super::*;
    use crate::{
        Cipher, CipherId, CipherRepromptType, CipherType, FieldType, Login, LoginView,
        PasswordHistoryView, VaultClientExt,
    };

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_USER_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const TEST_ORG_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";

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

    async fn create_client_with_wiremock(mock_server: &wiremock::MockServer) -> CiphersClient {
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
        let cipher = {
            let mut ctx = store.context();

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
                data: None,
            }
        };

        repository.set(cipher_id.to_string(), cipher).await.unwrap();
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
                .expect_put()
                .returning(move |_id, body| {
                    let body = body.unwrap();
                    Ok(CipherResponseModel {
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
                .once();
        });

        let repository = MemoryRepository::<Cipher>::default();
        repository_add_cipher(&repository, &store, cipher_id, "old_name").await;
        let cipher_view = generate_test_cipher();

        let request = cipher_view.try_into().unwrap();

        let result = edit_cipher(
            &store,
            &api_client,
            &repository,
            TEST_USER_ID.parse().unwrap(),
            request,
            false,
        )
        .await
        .unwrap();

        assert_eq!(result.id, Some(cipher_id));
        assert_eq!(result.name, "Test Login");
    }

    #[tokio::test]
    async fn test_edit_cipher_as_admin() {
        let (mock_server, _config) = start_api_mock(vec![
            Mock::given(method("PUT"))
                .and(path_regex(r"/ciphers/[a-f0-9-]+"))
                .respond_with(move |req: &wiremock::Request| {
                    let body_bytes = req.body.as_slice();
                    let request_body: CipherRequestModel =
                        serde_json::from_slice(body_bytes).expect("Failed to parse request body");

                    let response = CipherResponseModel {
                        id: Some(TEST_CIPHER_ID.try_into().unwrap()),
                        organization_id: request_body
                            .organization_id
                            .and_then(|id| id.parse().ok()),
                        name: Some(request_body.name.clone()),
                        r#type: request_body.r#type,
                        creation_date: Some(Utc::now().to_string()),
                        revision_date: Some(Utc::now().to_string()),
                        ..Default::default()
                    };

                    ResponseTemplate::new(200).set_body_json(&response)
                }),
        ])
        .await;
        let client = create_client_with_wiremock(&mock_server).await;
        let repository = client.get_repository().unwrap();

        let cipher_view = generate_test_cipher();
        repository
            .set(
                TEST_CIPHER_ID.to_string(),
                client.encrypt(cipher_view.clone()).unwrap().cipher,
            )
            .await
            .unwrap();

        let request = cipher_view.try_into().unwrap();
        let start_time = Utc::now();
        let result = client.edit_as_admin(request).await.unwrap();

        let cipher = repository.get(TEST_CIPHER_ID.to_string()).await.unwrap();
        // Should not update local repository for admin endpoints.
        assert!(result.revision_date > start_time);
        assert!(cipher.unwrap().revision_date < start_time);

        assert_eq!(result.id, TEST_CIPHER_ID.parse().ok());
        assert_eq!(result.name, "Test Login");
    }

    #[tokio::test]
    async fn test_edit_cipher_does_not_exist() {
        let store: KeyStore<KeyIds> = KeyStore::default();

        let repository = MemoryRepository::<Cipher>::default();

        let cipher_view = generate_test_cipher();
        let api_client = ApiClient::new_mocked(|_| {});

        let request = cipher_view.try_into().unwrap();

        let result = edit_cipher(
            &store,
            &api_client,
            &repository,
            TEST_USER_ID.parse().unwrap(),
            request,
            false,
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

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api.expect_put().returning(move |_id, _body| {
                Err(bitwarden_api_api::apis::Error::Io(std::io::Error::other(
                    "Simulated error",
                )))
            });
        });

        let repository = MemoryRepository::<Cipher>::default();
        repository_add_cipher(&repository, &store, cipher_id, "old_name").await;
        let cipher_view = generate_test_cipher();

        let request = cipher_view.try_into().unwrap();

        let result = edit_cipher(
            &store,
            &api_client,
            &repository,
            TEST_USER_ID.parse().unwrap(),
            request,
            false,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EditCipherError::Api(_)));
    }

    #[test]
    fn test_password_history_on_password_change() {
        let original_cipher = create_test_login_cipher("old_password");
        let edit_request =
            CipherEditRequest::try_from(create_test_login_cipher("new_password")).unwrap();

        let start = Utc::now();
        let internal_req = CipherEditRequestInternal::new(edit_request, &original_cipher);
        let history = internal_req.password_history;
        let end = Utc::now();

        assert_eq!(history.len(), 1);
        assert!(
            history[0].last_used_date >= start && history[0].last_used_date <= end,
            "last_used_date was not set properly"
        );
        assert_eq!(history[0].password, "old_password");
    }

    #[test]
    fn test_password_history_on_unchanged_password() {
        let original_cipher = create_test_login_cipher("same_password");
        let edit_request =
            CipherEditRequest::try_from(create_test_login_cipher("same_password")).unwrap();

        let internal_req = CipherEditRequestInternal::new(edit_request, &original_cipher);
        let password_history = internal_req.password_history;

        assert!(password_history.is_empty());
    }

    #[test]
    fn test_password_history_is_preserved() {
        let mut original_cipher = create_test_login_cipher("same_password");
        original_cipher.password_history = Some(
            (0..4)
                .map(|i| PasswordHistoryView {
                    password: format!("old_password_{}", i),
                    last_used_date: Utc.with_ymd_and_hms(2025, i + 1, i + 1, i, i, i).unwrap(),
                })
                .collect(),
        );

        let edit_request =
            CipherEditRequest::try_from(create_test_login_cipher("same_password")).unwrap();
        let internal_req = CipherEditRequestInternal::new(edit_request, &original_cipher);
        let history = internal_req.password_history;

        assert_eq!(history[0].password, "old_password_0");

        assert_eq!(
            history[0].last_used_date,
            Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap()
        );
        assert_eq!(history[1].password, "old_password_1");
        assert_eq!(
            history[1].last_used_date,
            Utc.with_ymd_and_hms(2025, 2, 2, 1, 1, 1).unwrap()
        );
        assert_eq!(history[2].password, "old_password_2");
        assert_eq!(
            history[2].last_used_date,
            Utc.with_ymd_and_hms(2025, 3, 3, 2, 2, 2).unwrap()
        );
        assert_eq!(history[3].password, "old_password_3");
        assert_eq!(
            history[3].last_used_date,
            Utc.with_ymd_and_hms(2025, 4, 4, 3, 3, 3).unwrap()
        );
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

        let edit_request = CipherEditRequest::try_from(new_cipher).unwrap();

        let internal_req = CipherEditRequestInternal::new(edit_request, &original_cipher);
        let history = internal_req.password_history;

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
        let edit_request =
            CipherEditRequest::try_from(create_test_login_cipher("new_password")).unwrap();

        let internal_req = CipherEditRequestInternal::new(edit_request, &original_cipher);
        let history = internal_req.password_history;

        assert_eq!(history.len(), MAX_PASSWORD_HISTORY_ENTRIES);
        // Most recent change (original password) should be first
        assert_eq!(history[0].password, "password");

        assert_eq!(history[1].password, "old_password_0");
        assert_eq!(history[2].password, "old_password_1");
        assert_eq!(history[3].password, "old_password_2");
        assert_eq!(history[4].password, "old_password_3");
    }
}
