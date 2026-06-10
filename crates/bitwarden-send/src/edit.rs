use bitwarden_core::{
    ApiError, MissingFieldError,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, IdentifyKey, KeyStore, KeyStoreContext, OctetStreamBytes,
    PrimitiveEncryptable,
};
use bitwarden_encoding::B64Url;
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
use uuid::Uuid;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    EmptyEmailListError, Send, SendAuthType, SendId, SendView, SendViewType,
    error::{ItemNotFoundError, SendParseError},
    send_client::SendClient,
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EditSendError {
    #[error(transparent)]
    ItemNotFound(#[from] ItemNotFoundError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    EmptyEmailList(#[from] EmptyEmailListError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    Uuid(#[from] uuid::Error),
    #[error(transparent)]
    SendParse(#[from] SendParseError),
    #[error("Server returned Send with ID {returned:?} but expected {expected}")]
    IdMismatch {
        expected: Uuid,
        returned: Option<Uuid>,
    },
}

/// Controls how `bw send edit` updates the auth on an existing Send.
///
/// The previous shape (`Option<SendAuthType>`) overloaded `Option` with a sentinel:
/// `None` did *not* mean "no auth", it meant "preserve". This enum encodes the
/// preserve-versus-overwrite distinction directly in the type so readers don't have
/// to recover the convention from doc-comments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum AuthEdit {
    /// Keep whatever auth the existing Send has. The SDK reads the encrypted-form
    /// `password`/`emails`/`auth_type` from the repository row and forwards them
    /// verbatim — no plaintext password is required.
    Preserve,
    /// Replace the existing auth with the supplied value. Pass `SendAuthType::None`
    /// to explicitly strip auth from the Send. The `auth` field is a named struct
    /// variant (not tuple) so the inner `SendAuthType`'s internally-tagged `"type"`
    /// key doesn't collide with this enum's own `"type"` tag on the wire.
    Set {
        /// The new auth configuration to apply.
        auth: SendAuthType,
    },
}

/// Request model for editing an existing Send.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendEditRequest {
    /// The name of the Send.
    pub name: String,
    /// Optional notes visible to the sender.
    pub notes: Option<String>,

    /// The type and content of the Send.
    pub view_type: SendViewType,

    /// Maximum number of times the Send can be accessed.
    pub max_access_count: Option<u32>,
    /// Whether the Send is disabled and cannot be accessed.
    pub disabled: bool,
    /// Whether to hide the sender's email from recipients.
    pub hide_email: bool,

    /// Date and time when the Send will be permanently deleted.
    pub deletion_date: DateTime<Utc>,
    /// Optional date and time when the Send expires and can no longer be accessed.
    pub expiration_date: Option<DateTime<Utc>>,

    /// Authentication method for accessing this Send.
    ///
    /// `AuthEdit::Set { auth: _ }` overwrites the existing auth (including switching to
    /// `SendAuthType::None` to remove all protection). `AuthEdit::Preserve` tells
    /// the SDK to forward the existing Send's `password` hash, email list, and
    /// `authType` discriminant verbatim to the server. Use `Preserve` when the
    /// caller is editing unrelated fields and must not silently strip a previously
    /// configured password or email-OTP gate.
    pub auth: AuthEdit,
}

/// Internal helper struct that includes the send key for encryption.
/// The key is retrieved from state during edit operations.
///
/// `preserved_auth` carries the encrypted-form auth fields (password hash, emails
/// comma-string, discriminant) read off the existing repository row when the caller asked
/// to preserve auth (`SendEditRequest.auth == AuthEdit::Preserve`). When `request.auth`
/// is `AuthEdit::Set { .. }`, this field is `None` and `request.auth` is the source of truth.
#[derive(Debug)]
struct SendEditRequestWithKey {
    request: SendEditRequest,
    send_key: String,
    preserved_auth: Option<PreservedAuth>,
}

/// Snapshot of an existing Send's wire-format auth fields, used to round-trip the auth
/// configuration through a partial edit without requiring the plaintext password.
#[derive(Debug)]
struct PreservedAuth {
    password: Option<String>,
    emails: Option<String>,
    auth_type: crate::AuthType,
}

impl
    CompositeEncryptable<
        KeySlotIds,
        SymmetricKeySlotId,
        bitwarden_api_api::models::SendRequestModel,
    > for SendEditRequestWithKey
{
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<bitwarden_api_api::models::SendRequestModel, CryptoError> {
        // Decode the send key from the existing send
        let k = B64Url::try_from(self.send_key.as_str())
            .map_err(|_| CryptoError::InvalidKey)?
            .as_bytes()
            .to_vec();

        let send_key = Send::derive_shareable_key(ctx, &k)?;

        let (send_type, file, text) = self
            .request
            .view_type
            .clone()
            .encrypt_composite(ctx, send_key)?;

        // Resolve auth from one of two sources, in order of precedence:
        //   1. `AuthEdit::Set { auth }` authoritatively overwrites the server-side auth (including
        //      switching to `SendAuthType::None` to remove protection).
        //   2. `AuthEdit::Preserve` forwards the snapshot read off the existing repository row,
        //      verbatim. This branch forwards the stored password hash and email list as-is, so a
        //      partial edit never silently strips a previously configured password or email-OTP
        //      gate.
        let (auth_type, password, emails) = match (&self.request.auth, &self.preserved_auth) {
            (AuthEdit::Set { auth }, _) => {
                let (password, emails) = auth.auth_data(&k);
                (auth.auth_type(), password, emails)
            }
            (AuthEdit::Preserve, Some(preserved)) => (
                preserved.auth_type,
                preserved.password.clone(),
                preserved.emails.clone(),
            ),
            // Unreachable in practice: `edit_send` always populates `preserved_auth` when
            // `request.auth` is `AuthEdit::Preserve`. Fall back to "no auth" defensively rather
            // than panicking from inside an encryption path.
            (AuthEdit::Preserve, None) => (crate::AuthType::None, None, None),
        };

        Ok(bitwarden_api_api::models::SendRequestModel {
            r#type: Some(send_type),
            auth_type: Some(auth_type.into()),
            file_length: None,
            name: Some(self.request.name.encrypt(ctx, send_key)?.to_string()),
            notes: self
                .request
                .notes
                .as_ref()
                .map(|n| n.encrypt(ctx, send_key))
                .transpose()?
                .map(|e| e.to_string()),
            // Encrypt the send key itself with the user key
            key: OctetStreamBytes::from(k).encrypt(ctx, key)?.to_string(),
            max_access_count: self.request.max_access_count.map(|c| c as i32),
            expiration_date: self.request.expiration_date.map(|d| d.to_rfc3339()),
            deletion_date: self.request.deletion_date.to_rfc3339(),
            file,
            text,
            password,
            emails,
            disabled: self.request.disabled,
            hide_email: Some(self.request.hide_email),
        })
    }
}

impl IdentifyKey<SymmetricKeySlotId> for SendEditRequestWithKey {
    fn key_identifier(&self) -> SymmetricKeySlotId {
        SymmetricKeySlotId::User
    }
}

async fn edit_send<R: Repository<Send> + ?Sized>(
    key_store: &KeyStore<KeySlotIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    send_id: SendId,
    request: SendEditRequest,
) -> Result<SendView, EditSendError> {
    // Only validate when the caller is asserting a new auth configuration; `Preserve`
    // means "use the existing row", which is already a server-validated value.
    if let AuthEdit::Set { auth } = &request.auth {
        auth.validate()?;
    }

    let id = send_id.to_string();

    // Retrieve the existing send to get its key (keys cannot be modified during edit)
    let existing_send = repository.get(send_id).await?.ok_or(ItemNotFoundError)?;

    // Snapshot the existing wire-format auth fields before we move out the key. These
    // are read directly off the encrypted `Send` (no decryption needed for `password`,
    // `emails`, or `auth_type`) so the SDK can round-trip auth on partial edits without
    // requiring the plaintext password back from the caller.
    let preserved_auth = matches!(request.auth, AuthEdit::Preserve).then(|| PreservedAuth {
        password: existing_send.password.clone(),
        emails: existing_send.emails.clone(),
        auth_type: existing_send.auth_type,
    });

    // Decrypt to get the key - we only need the key field
    let existing_send_view: SendView = key_store.decrypt(&existing_send)?;
    let send_key = existing_send_view.key.ok_or(MissingFieldError("key"))?;

    // Create the wrapper with the key from the existing send
    let request_with_key = SendEditRequestWithKey {
        request,
        send_key,
        preserved_auth,
    };

    let send_request = key_store.encrypt(request_with_key)?;

    let resp = api_client
        .sends_api()
        .put(&id, Some(send_request))
        .await
        .map_err(ApiError::from)?;

    let send: Send = resp.try_into()?;

    // Verify the server returned the correct send ID
    if send.id != Some(send_id) {
        return Err(EditSendError::IdMismatch {
            expected: send_id.into(),
            returned: send.id.map(Into::into),
        });
    }

    repository.set(send_id, send.clone()).await?;

    Ok(key_store.decrypt(&send)?)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl SendClient {
    /// Edit the [Send] and save it to the server.
    pub async fn edit(
        &self,
        send_id: SendId,
        request: SendEditRequest,
    ) -> Result<SendView, EditSendError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations();
        let repository = self.get_repository()?;

        edit_send(
            key_store,
            &config.api_client,
            repository.as_ref(),
            send_id,
            request,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::SendResponseModel};
    use bitwarden_core::key_management::SymmetricKeySlotId;
    use bitwarden_crypto::SymmetricKeyAlgorithm;
    use bitwarden_test::MemoryRepository;
    use chrono::{DateTime, Utc};
    use uuid::uuid;

    use super::*;
    use crate::{AuthType, SendTextView, SendType, SendViewType};

    /// `AuthEdit` is serialized with `#[serde(tag = "type")]`, and its `Set` variant
    /// carries a `SendAuthType` that *also* uses `#[serde(tag = "type")]`. With a tuple
    /// variant (`Set(SendAuthType)`) the inner type's tag would flatten into the outer
    /// object and collide with the outer tag, producing `{"type":"set","type":"password",...}`
    /// (invalid JSON; deserialize would fail with "duplicate field 'type'"). The struct
    /// variant `Set { auth: SendAuthType }` wraps the inner type in a sub-object instead,
    /// keeping the two `"type"` tags in separate scopes. This test pins the wire shape so
    /// the regression can't reappear.
    #[test]
    fn auth_edit_round_trips_through_json_without_duplicate_type_keys() {
        let cases = [
            (AuthEdit::Preserve, serde_json::json!({"type": "preserve"})),
            (
                AuthEdit::Set {
                    auth: SendAuthType::None,
                },
                serde_json::json!({"type": "set", "auth": {"type": "none"}}),
            ),
            (
                AuthEdit::Set {
                    auth: SendAuthType::Password {
                        password: "hunter2".to_string(),
                    },
                },
                serde_json::json!({
                    "type": "set",
                    "auth": {"type": "password", "password": "hunter2"}
                }),
            ),
            (
                AuthEdit::Set {
                    auth: SendAuthType::Emails {
                        emails: vec!["a@b.com".to_string(), "c@d.com".to_string()],
                    },
                },
                serde_json::json!({
                    "type": "set",
                    "auth": {"type": "emails", "emails": ["a@b.com", "c@d.com"]}
                }),
            ),
        ];
        for (value, expected_json) in cases {
            let serialized = serde_json::to_value(&value).expect("serialize");
            assert_eq!(
                serialized, expected_json,
                "wire shape mismatch for {value:?}"
            );
            let deserialized: AuthEdit = serde_json::from_value(serialized).expect("round-trip");
            assert_eq!(deserialized, value, "round-trip mismatch for {value:?}");
        }
    }

    #[tokio::test]
    async fn test_edit_send() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeySlotId::User)
                .unwrap();
        }

        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");

        // Pre-populate the repository with an existing send by encrypting a SendView
        let repository = MemoryRepository::<Send>::default();
        let existing_send_view = SendView {
            id: None, // No ID initially to allow key generation
            access_id: None,
            name: "original".to_string(),
            notes: Some("original notes".to_string()),
            key: None, // Generates a new key when first encrypted
            new_password: None,
            has_password: false,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("original text".to_string()),
                hidden: false,
            }),
            max_access_count: None,
            access_count: 0,
            disabled: false,
            hide_email: false,
            revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
            deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
            expiration_date: None,
            emails: Vec::new(),
            auth_type: AuthType::None,
        };
        let mut existing_send = store.encrypt(existing_send_view).unwrap();
        existing_send.id = Some(crate::send::SendId::new(send_id)); // Set the ID after encryption
        repository
            .set(SendId::new(send_id), existing_send)
            .await
            .unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api
                .expect_put()
                .returning(move |_id, model| {
                    let model = model.unwrap();
                    Ok(SendResponseModel {
                        id: Some(send_id),
                        name: model.name,
                        revision_date: Some("2025-01-02T00:00:00Z".to_string()),
                        object: Some("send".to_string()),
                        access_id: None,
                        r#type: model.r#type,
                        auth_type: model.auth_type,
                        notes: model.notes,
                        file: model.file,
                        text: model.text,
                        key: Some(model.key),
                        max_access_count: model.max_access_count,
                        access_count: Some(0),
                        password: model.password,
                        emails: model.emails,
                        disabled: Some(model.disabled),
                        expiration_date: model.expiration_date,
                        deletion_date: Some(model.deletion_date),
                        hide_email: model.hide_email,
                    })
                })
                .once();
        });

        let result = edit_send(
            &store,
            &api_client,
            &repository,
            SendId::new(send_id),
            SendEditRequest {
                name: "updated".to_string(),
                notes: Some("updated notes".to_string()),
                view_type: SendViewType::Text(SendTextView {
                    text: Some("updated text".to_string()),
                    hidden: false,
                }),
                max_access_count: None,
                disabled: false,
                hide_email: false,
                deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
                expiration_date: None,
                auth: AuthEdit::Set {
                    auth: SendAuthType::None,
                },
            },
        )
        .await
        .unwrap();

        // Verify the result
        assert_eq!(result.id, Some(crate::send::SendId::new(send_id)));
        assert_eq!(result.name, "updated");
        assert_eq!(result.notes, Some("updated notes".to_string()));
        assert!(result.key.is_some(), "Expected a key");
        assert_eq!(
            result.revision_date,
            "2025-01-02T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );

        // Confirm the send was updated in the repository
        let stored = repository.get(SendId::new(send_id)).await.unwrap().unwrap();
        assert_eq!(
            store
                .decrypt::<SymmetricKeySlotId, Send, SendView>(&stored)
                .unwrap()
                .name,
            "updated"
        );
    }

    #[tokio::test]
    async fn test_edit_send_not_found() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeySlotId::User)
                .unwrap();
        }

        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let repository = MemoryRepository::<Send>::default();
        let api_client = ApiClient::new_mocked(move |_mock| {});

        let result = edit_send(
            &store,
            &api_client,
            &repository,
            SendId::new(send_id),
            SendEditRequest {
                name: "test".to_string(),
                notes: None,
                view_type: SendViewType::Text(SendTextView {
                    text: Some("test".to_string()),
                    hidden: false,
                }),
                max_access_count: None,
                disabled: false,
                hide_email: false,
                deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
                expiration_date: None,
                auth: AuthEdit::Set {
                    auth: SendAuthType::None,
                },
            },
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EditSendError::ItemNotFound(_)
        ));
    }

    #[tokio::test]
    async fn test_edit_send_http_error() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeySlotId::User)
                .unwrap();
        }

        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");

        // Pre-populate the repository with an existing send by encrypting a SendView
        let repository = MemoryRepository::<Send>::default();
        let existing_send_view = SendView {
            id: None, // No ID initially to allow key generation
            access_id: None,
            name: "original".to_string(),
            notes: Some("original notes".to_string()),
            key: None, // Generates a new key when first encrypted
            new_password: None,
            has_password: false,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("original text".to_string()),
                hidden: false,
            }),
            max_access_count: None,
            access_count: 0,
            disabled: false,
            hide_email: false,
            revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
            deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
            expiration_date: None,
            emails: Vec::new(),
            auth_type: AuthType::None,
        };
        let mut existing_send = store.encrypt(existing_send_view).unwrap();
        existing_send.id = Some(crate::send::SendId::new(send_id)); // Set the ID after encryption
        repository
            .set(SendId::new(send_id), existing_send)
            .await
            .unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api
                .expect_put()
                .returning(move |_id, _model| Err(std::io::Error::other("Simulated error").into()));
        });

        let result = edit_send(
            &store,
            &api_client,
            &repository,
            SendId::new(send_id),
            SendEditRequest {
                name: "test".to_string(),
                notes: None,
                view_type: SendViewType::Text(SendTextView {
                    text: Some("test".to_string()),
                    hidden: false,
                }),
                max_access_count: None,
                disabled: false,
                hide_email: false,
                deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
                expiration_date: None,
                auth: AuthEdit::Set {
                    auth: SendAuthType::None,
                },
            },
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EditSendError::Api(_)));
    }

    /// Builds a key store / repository fixture pre-populated with a Send whose encrypted
    /// row carries the provided `password_hash`, `emails`, and `auth_type`. We construct
    /// the encrypted `Send` directly (rather than going through `encrypt(SendView)`)
    /// because `SendView` deliberately doesn't surface the password hash — those fields
    /// only live on the wire-format `Send` struct.
    async fn make_fixture_with_existing_auth(
        send_id: uuid::Uuid,
        password_hash: Option<String>,
        emails: Option<String>,
        auth_type: AuthType,
    ) -> (KeyStore<KeySlotIds>, MemoryRepository<Send>) {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeySlotId::User)
                .unwrap();
        }

        // Encrypt a baseline view to get realistic name/text/key ciphertext, then patch the
        // wire-format auth fields onto the encrypted row.
        let baseline = SendView {
            id: None,
            access_id: None,
            name: "original".to_string(),
            notes: None,
            key: None,
            new_password: None,
            has_password: false,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("secret".to_string()),
                hidden: false,
            }),
            max_access_count: None,
            access_count: 0,
            disabled: false,
            hide_email: false,
            revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
            deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
            expiration_date: None,
            emails: Vec::new(),
            auth_type: AuthType::None,
        };
        let mut existing_send = store.encrypt(baseline).unwrap();
        existing_send.id = Some(crate::send::SendId::new(send_id));
        existing_send.password = password_hash;
        existing_send.emails = emails;
        existing_send.auth_type = auth_type;

        let repository = MemoryRepository::<Send>::default();
        repository
            .set(SendId::new(send_id), existing_send)
            .await
            .unwrap();

        (store, repository)
    }

    /// Drives `edit_send` against a fixture and captures the `SendRequestModel` that the
    /// SDK would have sent to the server. We don't care about the round-trip response
    /// content here — the assertion lives on the request body.
    async fn capture_edit_put_model(
        store: &KeyStore<KeySlotIds>,
        repository: &MemoryRepository<Send>,
        send_id: uuid::Uuid,
        request: SendEditRequest,
    ) -> bitwarden_api_api::models::SendRequestModel {
        let captured: std::sync::Arc<
            std::sync::Mutex<Option<bitwarden_api_api::models::SendRequestModel>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(None));
        let sink = captured.clone();

        let api_client = ApiClient::new_mocked(move |mock| {
            let sink = sink.clone();
            mock.sends_api
                .expect_put()
                .returning(move |_id, model| {
                    let model = model.unwrap();
                    *sink.lock().unwrap() = Some(model.clone());
                    Ok(SendResponseModel {
                        id: Some(send_id),
                        name: model.name.clone(),
                        revision_date: Some("2025-01-02T00:00:00Z".to_string()),
                        object: Some("send".to_string()),
                        access_id: None,
                        r#type: model.r#type,
                        auth_type: model.auth_type,
                        notes: model.notes.clone(),
                        file: model.file.clone(),
                        text: model.text.clone(),
                        key: Some(model.key.clone()),
                        max_access_count: model.max_access_count,
                        access_count: Some(0),
                        password: model.password.clone(),
                        emails: model.emails.clone(),
                        disabled: Some(model.disabled),
                        expiration_date: model.expiration_date.clone(),
                        deletion_date: Some(model.deletion_date.clone()),
                        hide_email: model.hide_email,
                    })
                })
                .once();
        });

        edit_send(
            store,
            &api_client,
            repository,
            SendId::new(send_id),
            request,
        )
        .await
        .unwrap();

        captured.lock().unwrap().take().expect("PUT was not called")
    }

    /// Regression test for the auth-strip bug. With the previous `auth: SendAuthType`
    /// (non-optional) field, the CLI passed `SendAuthType::None` whenever the user ran
    /// `bw send edit` without auth flags, and the server treated that as an overwrite
    /// that cleared the password. With `auth: AuthEdit` and `AuthEdit::Preserve` as the
    /// no-auth-flags case, the SDK forwards the existing password hash verbatim.
    #[tokio::test]
    async fn test_edit_preserves_existing_password_when_auth_is_none() {
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let existing_hash = "abc123hashstub==".to_string();
        let (store, repository) = make_fixture_with_existing_auth(
            send_id,
            Some(existing_hash.clone()),
            None,
            AuthType::Password,
        )
        .await;

        let model = capture_edit_put_model(
            &store,
            &repository,
            send_id,
            SendEditRequest {
                name: "updated".to_string(),
                notes: None,
                view_type: SendViewType::Text(SendTextView {
                    text: Some("secret".to_string()),
                    hidden: false,
                }),
                max_access_count: None,
                disabled: false,
                hide_email: false,
                deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
                expiration_date: None,
                auth: AuthEdit::Preserve,
            },
        )
        .await;

        assert_eq!(
            model.password,
            Some(existing_hash),
            "preserve-mode edit must forward the existing password hash to the server",
        );
        assert_eq!(model.emails, None);
        assert_eq!(
            model.auth_type,
            Some(bitwarden_api_api::models::AuthType::Password),
        );
    }

    #[tokio::test]
    async fn test_edit_preserves_existing_emails_when_auth_is_none() {
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let existing_emails = "a@b.com,c@d.com".to_string();
        let (store, repository) = make_fixture_with_existing_auth(
            send_id,
            None,
            Some(existing_emails.clone()),
            AuthType::Email,
        )
        .await;

        let model = capture_edit_put_model(
            &store,
            &repository,
            send_id,
            SendEditRequest {
                name: "updated".to_string(),
                notes: None,
                view_type: SendViewType::Text(SendTextView {
                    text: Some("secret".to_string()),
                    hidden: false,
                }),
                max_access_count: None,
                disabled: false,
                hide_email: false,
                deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
                expiration_date: None,
                auth: AuthEdit::Preserve,
            },
        )
        .await;

        assert_eq!(model.password, None);
        assert_eq!(model.emails, Some(existing_emails));
        assert_eq!(
            model.auth_type,
            Some(bitwarden_api_api::models::AuthType::Email),
        );
    }

    #[tokio::test]
    async fn test_edit_preserves_no_auth_when_auth_is_none() {
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let (store, repository) =
            make_fixture_with_existing_auth(send_id, None, None, AuthType::None).await;

        let model = capture_edit_put_model(
            &store,
            &repository,
            send_id,
            SendEditRequest {
                name: "updated".to_string(),
                notes: None,
                view_type: SendViewType::Text(SendTextView {
                    text: Some("secret".to_string()),
                    hidden: false,
                }),
                max_access_count: None,
                disabled: false,
                hide_email: false,
                deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
                expiration_date: None,
                auth: AuthEdit::Preserve,
            },
        )
        .await;

        assert_eq!(model.password, None);
        assert_eq!(model.emails, None);
        assert_eq!(
            model.auth_type,
            Some(bitwarden_api_api::models::AuthType::None),
        );
    }

    /// An explicit `AuthEdit::Set { auth: SendAuthType::None }` still means "remove protection" —
    /// that's the escape hatch a caller uses to deliberately strip auth (mirroring the
    /// legacy `bw send remove-password` semantics for the auth slot generally).
    #[tokio::test]
    async fn test_edit_explicit_auth_none_overrides_existing_password() {
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let (store, repository) = make_fixture_with_existing_auth(
            send_id,
            Some("existing-hash".to_string()),
            None,
            AuthType::Password,
        )
        .await;

        let model = capture_edit_put_model(
            &store,
            &repository,
            send_id,
            SendEditRequest {
                name: "updated".to_string(),
                notes: None,
                view_type: SendViewType::Text(SendTextView {
                    text: Some("secret".to_string()),
                    hidden: false,
                }),
                max_access_count: None,
                disabled: false,
                hide_email: false,
                deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
                expiration_date: None,
                auth: AuthEdit::Set {
                    auth: SendAuthType::None,
                },
            },
        )
        .await;

        assert_eq!(model.password, None);
        assert_eq!(model.emails, None);
        assert_eq!(
            model.auth_type,
            Some(bitwarden_api_api::models::AuthType::None),
        );
    }
}
