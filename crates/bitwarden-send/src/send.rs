use bitwarden_api_api::models::{
    SendDataModel, SendFileModel, SendItemMetadataModel, SendResponseModel, SendTextModel,
    SendWithIdRequestModel,
};
use bitwarden_core::{
    key_management::{KeySlotIds, SymmetricKeySlotId},
    require,
};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, Decryptable, EncString, IdentifyKey, KeyStoreContext,
    OctetStreamBytes, PrimitiveEncryptable, generate_random_bytes,
};
use bitwarden_encoding::{B64, B64Url};
use bitwarden_uuid::uuid_newtype;
use bitwarden_vault::{CipherId, CipherView};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use thiserror::Error;
use zeroize::Zeroizing;
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

use crate::{SendParseError, access::SEND_KEY_LEN, error::SendItemDeserializationFailureError};
pub const SEND_ITERATIONS: u32 = 100_000;
pub const DEFAULT_SEND_ENCRYPTION: SendEncryptionType = SendEncryptionType::V1;

uuid_newtype!(pub SendId);

/// Error returned when `SendAuthType::Emails` is constructed with an empty email list.
#[derive(Debug, Error)]
#[error("Email authentication requires at least one email address")]
pub struct EmptyEmailListError;

/// File-based send content
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendFile {
    /// The file's ID
    pub id: Option<String>,
    /// The encrypted file name
    pub file_name: EncString,
    /// The file size in bytes as a string
    pub size: Option<String>,
    /// Readable size, ex: "4.2 KB" or "1.43 GB"
    pub size_name: Option<String>,
}

/// View model for decrypted SendFile
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendFileView {
    /// The file's ID
    pub id: Option<String>,
    /// The file name
    pub file_name: String,
    /// The file size in bytes as a string
    pub size: Option<String>,
    /// Readable size, ex: "4.2 KB" or "1.43 GB"
    pub size_name: Option<String>,
}

/// Text-based send content
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendText {
    pub text: Option<EncString>,
    pub hidden: bool,
}

/// View model for decrypted SendItem
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendItemView {
    /// The item content of the send
    pub data: CipherView,
}

/// Item-based send content
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendItem {
    pub encryption_version: SendEncryptionType,
    /// Opaque sealed cipher blob, see [`CipherView::seal_blob_for_item_sends`].
    pub data: String,
    pub metadata: SendItemMetadata,
}

/// Unencrypted metadata of an Item Send
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendItemMetadata {
    /// Id of the vault item being sent
    pub item_id: CipherId,
}

/// View model for decrypted SendText
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendTextView {
    /// The text content of the send
    pub text: Option<String>,
    /// Whether the text is hidden-by-default (masked as ********).
    pub hidden: bool,
}

/// The type of Send, either text, file, or item
#[derive(Clone, Copy, Serialize_repr, Deserialize_repr, Debug, PartialEq)]
#[repr(u8)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum SendType {
    /// Text-based send
    Text = 0,
    /// File-based send
    File = 1,
    /// Item-based send
    Item = 2,
}

/// Indicates the authentication strategy to use when accessing a Send
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum AuthType {
    /// Email-based OTP authentication
    Email = 0,

    /// Password-based authentication
    Password = 1,

    /// No authentication required
    None = 2,
}

/// Indicates the version of Send data encryption that is being used
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum SendEncryptionType {
    /// V1 encryption (field by field)
    V1 = 1,
}

/// Type-safe authentication method for a Send, including the authentication data.
/// This ensures that password and email authentication are mutually exclusive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum SendAuthType {
    /// No authentication required
    None,
    /// Password-based authentication. The SDK derives the wire-format `keyB64` via PBKDF2
    /// over the send key.
    Password {
        /// The plaintext password the recipient will enter to access the Send.
        password: String,
    },
    /// Pre-derived password. The caller has already run PBKDF2 client-side and supplies the
    /// resulting base64-encoded hash; the SDK forwards it verbatim. Use this when the
    /// hashing happens outside the SDK (e.g. the legacy TypeScript clients that derive in
    /// `SendService.encrypt`). For new code that holds a plaintext password, use
    /// `Password { ... }` and let the SDK do the derivation.
    HashedPassword {
        /// Base64-encoded PBKDF2 output (`keyB64`) ready for the wire.
        #[serde(rename = "keyB64")]
        key_b64: String,
    },
    /// Email-based OTP authentication
    Emails {
        /// List of email addresses that will receive OTP codes
        emails: Vec<String>,
    },
}

impl SendAuthType {
    /// Construct a `Password` variant from a plaintext password. The SDK will run PBKDF2
    /// during encryption.
    pub fn from_plaintext_password(password: String) -> Self {
        SendAuthType::Password { password }
    }

    /// Construct a `HashedPassword` variant from an already-derived `keyB64`. The SDK
    /// forwards it verbatim — no further derivation. Misuse (passing plaintext here)
    /// produces an unsatisfiable server-side hash.
    pub fn from_hashed_password(key_b64: String) -> Self {
        SendAuthType::HashedPassword { key_b64 }
    }

    /// Returns the AuthType discriminant for this authentication method
    pub fn auth_type(&self) -> AuthType {
        match self {
            SendAuthType::None => AuthType::None,
            SendAuthType::Password { .. } | SendAuthType::HashedPassword { .. } => {
                AuthType::Password
            }
            SendAuthType::Emails { .. } => AuthType::Email,
        }
    }

    /// Validates that the auth configuration is valid.
    /// Returns an error if `Emails` is used with an empty list.
    pub(crate) fn validate(&self) -> Result<(), EmptyEmailListError> {
        if let SendAuthType::Emails { emails } = self
            && emails.is_empty()
        {
            return Err(EmptyEmailListError);
        }
        Ok(())
    }

    /// Returns `(password, emails)` for the wire request. For `Password`, runs PBKDF2 over
    /// the plaintext using `k` as the salt. For `HashedPassword`, forwards the supplied
    /// `keyB64` verbatim — `k` is unused on that branch.
    pub(crate) fn auth_data(&self, k: &[u8]) -> (Option<String>, Option<String>) {
        match self {
            SendAuthType::Password { password } => {
                let hashed = bitwarden_crypto::pbkdf2(password.as_bytes(), k, SEND_ITERATIONS);
                (Some(B64::from(hashed.as_slice()).to_string()), None)
            }
            SendAuthType::HashedPassword { key_b64 } => (Some(key_b64.clone()), None),
            SendAuthType::Emails { emails } => {
                let emails_str = if emails.is_empty() {
                    None
                } else {
                    Some(emails.join(","))
                };
                (None, emails_str)
            }
            SendAuthType::None => (None, None),
        }
    }
}

/// View model for decrypted Send type
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum SendViewType {
    /// File-based send
    File(SendFileView),
    /// Text-based send
    Text(SendTextView),
    /// Item-based send
    Item(Box<SendItemView>),
}

/// Type alias for the tuple returned by SendViewType::into_api_models
type SendApiModels = (
    bitwarden_api_api::models::SendType,
    Option<Box<bitwarden_api_api::models::SendFileModel>>,
    Option<Box<bitwarden_api_api::models::SendTextModel>>,
    Option<Box<bitwarden_api_api::models::SendDataModel>>,
);

impl CompositeEncryptable<KeySlotIds, SymmetricKeySlotId, SendApiModels> for SendViewType {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<SendApiModels, CryptoError> {
        match self {
            SendViewType::File(f) => Ok((
                bitwarden_api_api::models::SendType::File,
                Some(Box::new(bitwarden_api_api::models::SendFileModel {
                    id: f.id.clone(),
                    file_name: Some(f.file_name.encrypt(ctx, key)?.to_string()),
                    size: f.size.clone(),
                    size_name: f.size_name.clone(),
                })),
                None,
                None,
            )),
            SendViewType::Text(t) => Ok((
                bitwarden_api_api::models::SendType::Text,
                None,
                Some(Box::new(bitwarden_api_api::models::SendTextModel {
                    text: t
                        .text
                        .as_ref()
                        .map(|txt| txt.encrypt(ctx, key))
                        .transpose()?
                        .map(|e| e.to_string()),
                    hidden: Some(t.hidden),
                })),
                None,
            )),
            SendViewType::Item(i) => {
                let encrypted = i.encrypt_composite(ctx, key)?;
                Ok((
                    bitwarden_api_api::models::SendType::Item,
                    None,
                    None,
                    Some(Box::new(encrypted.into())),
                ))
            }
        }
    }
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct Send {
    pub id: Option<SendId>,
    pub access_id: Option<String>,

    pub name: EncString,
    pub notes: Option<EncString>,
    pub key: EncString,
    pub password: Option<String>,

    pub r#type: SendType,
    pub file: Option<SendFile>,
    pub text: Option<SendText>,
    pub data: Option<SendItem>,

    pub max_access_count: Option<u32>,
    pub access_count: u32,
    pub disabled: bool,
    pub hide_email: bool,

    pub revision_date: DateTime<Utc>,
    pub deletion_date: DateTime<Utc>,
    pub expiration_date: Option<DateTime<Utc>>,

    /// Email addresses for OTP authentication (comma-separated).
    ///
    /// **Note**: Mutually exclusive with `password`. If both `password` and `emails` are
    /// set, password authentication takes precedence and email OTP is ignored.
    pub emails: Option<String>,
    pub auth_type: AuthType,
}

bitwarden_state::register_repository_item!(SendId => Send, "Send");

impl From<Send> for SendWithIdRequestModel {
    fn from(send: Send) -> Self {
        let file_length = send.file.as_ref().and_then(|file| {
            file.size
                .as_deref()
                .and_then(|size| size.parse::<i64>().ok())
        });

        SendWithIdRequestModel {
            r#type: Some(send.r#type.into()),
            auth_type: Some(send.auth_type.into()),
            file_length,
            name: Some(send.name.to_string()),
            notes: send.notes.map(|notes| notes.to_string()),
            key: send.key.to_string(),
            max_access_count: send.max_access_count.map(|count| count as i32),
            expiration_date: send.expiration_date.map(|date| date.to_rfc3339()),
            deletion_date: send.deletion_date.to_rfc3339(),
            file: send.file.map(|file| Box::new(file.into())),
            text: send.text.map(|text| Box::new(text.into())),
            data: send.data.map(|data| Box::new(data.into())),
            password: send.password,
            emails: send.emails,
            disabled: send.disabled,
            hide_email: Some(send.hide_email),
            id: send
                .id
                .expect("SendWithIdRequestModel conversion requires send id")
                .into(),
        }
    }
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendView {
    pub id: Option<SendId>,
    pub access_id: Option<String>,

    pub name: String,
    pub notes: Option<String>,
    /// Base64 encoded key
    pub key: Option<String>,
    /// Replace or add a password to an existing send. The SDK will always return None when
    /// decrypting a [Send]
    /// TODO: We should revisit this, one variant is to have `[Create, Update]SendView` DTOs.
    pub new_password: Option<String>,
    /// Denote if an existing send has a password. The SDK will ignore this value when creating or
    /// updating sends.
    pub has_password: bool,

    pub r#type: SendType,
    pub file: Option<SendFileView>,
    pub text: Option<SendTextView>,
    pub data: Option<SendItemView>,

    pub max_access_count: Option<u32>,
    pub access_count: u32,
    pub disabled: bool,
    pub hide_email: bool,

    pub revision_date: DateTime<Utc>,
    pub deletion_date: DateTime<Utc>,
    pub expiration_date: Option<DateTime<Utc>>,

    /// Email addresses for OTP authentication.
    /// **Note**: Mutually exclusive with `new_password`. If both are set, only password
    /// authentication will be used. When creating or editing sends, use [crate::SendAuthType]
    /// to ensure mutual exclusivity at the type level.
    pub emails: Vec<String>,
    pub auth_type: AuthType,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendListView {
    pub id: Option<SendId>,
    pub access_id: Option<String>,

    pub name: String,

    pub r#type: SendType,
    pub disabled: bool,

    pub revision_date: DateTime<Utc>,
    pub deletion_date: DateTime<Utc>,
    pub expiration_date: Option<DateTime<Utc>>,

    pub auth_type: AuthType,
}

impl Send {
    #[allow(missing_docs)]
    pub fn get_key(
        ctx: &mut KeyStoreContext<KeySlotIds>,
        send_key: &EncString,
        enc_key: SymmetricKeySlotId,
    ) -> Result<SymmetricKeySlotId, CryptoError> {
        let key: Vec<u8> = send_key.decrypt(ctx, enc_key)?;
        Self::derive_shareable_key(ctx, &key)
    }

    pub(crate) fn derive_shareable_key(
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: &[u8],
    ) -> Result<SymmetricKeySlotId, CryptoError> {
        let key = Zeroizing::new(key.try_into().map_err(|_| CryptoError::InvalidKeyLen)?);
        ctx.derive_shareable_key(key, "send", Some("send"))
    }
}

impl IdentifyKey<SymmetricKeySlotId> for Send {
    fn key_identifier(&self) -> SymmetricKeySlotId {
        SymmetricKeySlotId::User
    }
}

impl IdentifyKey<SymmetricKeySlotId> for SendView {
    fn key_identifier(&self) -> SymmetricKeySlotId {
        SymmetricKeySlotId::User
    }
}

impl Decryptable<KeySlotIds, SymmetricKeySlotId, SendTextView> for SendText {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<SendTextView, CryptoError> {
        Ok(SendTextView {
            text: self.text.decrypt(ctx, key)?,
            hidden: self.hidden,
        })
    }
}

impl CompositeEncryptable<KeySlotIds, SymmetricKeySlotId, SendText> for SendTextView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<SendText, CryptoError> {
        Ok(SendText {
            text: self.text.encrypt(ctx, key)?,
            hidden: self.hidden,
        })
    }
}

impl Decryptable<KeySlotIds, SymmetricKeySlotId, SendFileView> for SendFile {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<SendFileView, CryptoError> {
        Ok(SendFileView {
            id: self.id.clone(),
            file_name: self.file_name.decrypt(ctx, key)?,
            size: self.size.clone(),
            size_name: self.size_name.clone(),
        })
    }
}

impl CompositeEncryptable<KeySlotIds, SymmetricKeySlotId, SendFile> for SendFileView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<SendFile, CryptoError> {
        Ok(SendFile {
            id: self.id.clone(),
            file_name: self.file_name.encrypt(ctx, key)?,
            size: self.size.clone(),
            size_name: self.size_name.clone(),
        })
    }
}

impl Decryptable<KeySlotIds, SymmetricKeySlotId, SendItemView> for SendItem {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<SendItemView, CryptoError> {
        let mut data = CipherView::unseal_blob_for_item_sends(&self.data, ctx, key)?;
        // The blob holds no id; restore it from the metadata.
        data.id = Some(self.metadata.item_id);
        Ok(SendItemView { data })
    }
}

impl CompositeEncryptable<KeySlotIds, SymmetricKeySlotId, SendItem> for SendItemView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<SendItem, CryptoError> {
        Ok(SendItem {
            encryption_version: DEFAULT_SEND_ENCRYPTION,
            data: self.data.seal_blob_for_item_sends(ctx, key)?,
            metadata: SendItemMetadata {
                item_id: self.data.id.ok_or(CryptoError::MissingField("id"))?,
            },
        })
    }
}

impl Decryptable<KeySlotIds, SymmetricKeySlotId, SendView> for Send {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<SendView, CryptoError> {
        // For sends, we first decrypt the send key with the user key, and stretch it to it's full
        // size For the rest of the fields, we ignore the provided SymmetricCryptoKey and
        // the stretched key
        let k: Vec<u8> = self.key.decrypt(ctx, key)?;
        let key = Send::derive_shareable_key(ctx, &k)?;

        Ok(SendView {
            id: self.id,
            access_id: self.access_id.clone(),

            name: self.name.decrypt(ctx, key).ok().unwrap_or_default(),
            notes: self.notes.decrypt(ctx, key).ok().flatten(),
            key: Some(B64Url::from(k).to_string()),
            new_password: None,
            has_password: self.password.is_some(),

            r#type: self.r#type,
            file: self.file.decrypt(ctx, key).ok().flatten(),
            text: self.text.decrypt(ctx, key).ok().flatten(),
            data: self.data.decrypt(ctx, key).ok().flatten(),

            max_access_count: self.max_access_count,
            access_count: self.access_count,
            disabled: self.disabled,
            hide_email: self.hide_email,

            revision_date: self.revision_date,
            deletion_date: self.deletion_date,
            expiration_date: self.expiration_date,

            emails: self
                .emails
                .as_deref()
                .unwrap_or_default()
                .split(',')
                .map(|e| e.trim())
                .filter(|e| !e.is_empty())
                .map(String::from)
                .collect(),
            auth_type: self.auth_type,
        })
    }
}

impl Decryptable<KeySlotIds, SymmetricKeySlotId, SendListView> for Send {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<SendListView, CryptoError> {
        // For sends, we first decrypt the send key with the user key, and stretch it to it's full
        // size For the rest of the fields, we ignore the provided SymmetricCryptoKey and
        // the stretched key
        let key = Send::get_key(ctx, &self.key, key)?;

        Ok(SendListView {
            id: self.id,
            access_id: self.access_id.clone(),

            name: self.name.decrypt(ctx, key)?,
            r#type: self.r#type,

            disabled: self.disabled,

            revision_date: self.revision_date,
            deletion_date: self.deletion_date,
            expiration_date: self.expiration_date,

            auth_type: self.auth_type,
        })
    }
}

impl CompositeEncryptable<KeySlotIds, SymmetricKeySlotId, Send> for SendView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<Send, CryptoError> {
        // For sends, we first decrypt the send key with the user key, and stretch it to it's full
        // size For the rest of the fields, we ignore the provided SymmetricCryptoKey and
        // the stretched key
        let k = match (&self.key, &self.id) {
            // Existing send, decrypt key
            (Some(k), _) => B64Url::try_from(k.as_str())
                .map_err(|_| CryptoError::InvalidKey)?
                .as_bytes()
                .to_vec(),
            // New send, generate random key
            (None, None) => {
                let key = generate_random_bytes::<[u8; SEND_KEY_LEN]>();
                key.to_vec()
            }
            // Existing send without key
            _ => return Err(CryptoError::InvalidKey),
        };
        let send_key = Send::derive_shareable_key(ctx, &k)?;

        Ok(Send {
            id: self.id,
            access_id: self.access_id.clone(),

            name: self.name.encrypt(ctx, send_key)?,
            notes: self.notes.encrypt(ctx, send_key)?,
            key: OctetStreamBytes::from(k.clone()).encrypt(ctx, key)?,
            // A decrypted SendView never carries the existing password hash (only
            // `has_password`), so a call site with no new password to set (e.g. key rotation)
            // always produces `password: None` here. This is safe: the server's rotation and
            // edit validators special-case AuthType::Password on both the stored and incoming
            // record and preserve the stored hash unconditionally in that case, ignoring
            // whatever this field carries. See `ToSendBase` server-side.
            password: self.new_password.as_ref().map(|password| {
                let password = bitwarden_crypto::pbkdf2(password.as_bytes(), &k, SEND_ITERATIONS);
                B64::from(password.as_slice()).to_string()
            }),

            r#type: self.r#type,
            file: self.file.encrypt_composite(ctx, send_key)?,
            text: self.text.encrypt_composite(ctx, send_key)?,
            data: self.data.encrypt_composite(ctx, send_key)?,

            max_access_count: self.max_access_count,
            access_count: self.access_count,
            disabled: self.disabled,
            hide_email: self.hide_email,

            revision_date: self.revision_date,
            deletion_date: self.deletion_date,
            expiration_date: self.expiration_date,

            emails: (!self.emails.is_empty()).then(|| self.emails.join(",")),
            auth_type: self.auth_type,
        })
    }
}

impl TryFrom<SendResponseModel> for Send {
    type Error = SendParseError;

    fn try_from(send: SendResponseModel) -> Result<Self, Self::Error> {
        let auth_type = match send.auth_type {
            Some(t) => t.try_into()?,
            None => {
                if send.password.is_some() {
                    AuthType::Password
                } else if send.emails.is_some() {
                    AuthType::Email
                } else {
                    AuthType::None
                }
            }
        };
        Ok(Send {
            id: send.id.map(SendId::new),
            access_id: send.access_id,
            name: require!(send.name).parse()?,
            notes: EncString::try_from_optional(send.notes)?,
            key: require!(send.key).parse()?,
            password: send.password,
            r#type: require!(send.r#type).try_into()?,
            file: send.file.map(|f| (*f).try_into()).transpose()?,
            text: send.text.map(|t| (*t).try_into()).transpose()?,
            data: send.data.map(|d| (*d).try_into()).transpose()?,
            max_access_count: send.max_access_count.map(|s| s as u32),
            access_count: require!(send.access_count) as u32,
            disabled: send.disabled.unwrap_or(false),
            hide_email: send.hide_email.unwrap_or(false),
            revision_date: require!(send.revision_date).parse()?,
            deletion_date: require!(send.deletion_date).parse()?,
            expiration_date: send.expiration_date.map(|s| s.parse()).transpose()?,
            emails: send.emails,
            auth_type,
        })
    }
}

impl TryFrom<bitwarden_api_api::models::SendType> for SendType {
    type Error = bitwarden_core::MissingFieldError;

    fn try_from(t: bitwarden_api_api::models::SendType) -> Result<Self, Self::Error> {
        Ok(match t {
            bitwarden_api_api::models::SendType::Text => SendType::Text,
            bitwarden_api_api::models::SendType::File => SendType::File,
            bitwarden_api_api::models::SendType::Item => SendType::Item,
            bitwarden_api_api::models::SendType::__Unknown(_) => {
                return Err(bitwarden_core::MissingFieldError("type"));
            }
        })
    }
}

impl From<SendType> for bitwarden_api_api::models::SendType {
    fn from(t: SendType) -> Self {
        match t {
            SendType::Text => bitwarden_api_api::models::SendType::Text,
            SendType::File => bitwarden_api_api::models::SendType::File,
            SendType::Item => bitwarden_api_api::models::SendType::Item,
        }
    }
}

impl TryFrom<bitwarden_api_api::models::AuthType> for AuthType {
    type Error = bitwarden_core::MissingFieldError;

    fn try_from(value: bitwarden_api_api::models::AuthType) -> Result<Self, Self::Error> {
        Ok(match value {
            bitwarden_api_api::models::AuthType::Email => AuthType::Email,
            bitwarden_api_api::models::AuthType::Password => AuthType::Password,
            bitwarden_api_api::models::AuthType::None => AuthType::None,
            bitwarden_api_api::models::AuthType::__Unknown(_) => {
                return Err(bitwarden_core::MissingFieldError("auth_type"));
            }
        })
    }
}

impl From<AuthType> for bitwarden_api_api::models::AuthType {
    fn from(value: AuthType) -> Self {
        match value {
            AuthType::Email => bitwarden_api_api::models::AuthType::Email,
            AuthType::Password => bitwarden_api_api::models::AuthType::Password,
            AuthType::None => bitwarden_api_api::models::AuthType::None,
        }
    }
}

impl From<SendFile> for SendFileModel {
    fn from(file: SendFile) -> Self {
        SendFileModel {
            id: file.id,
            file_name: Some(file.file_name.to_string()),
            size: file.size,
            size_name: file.size_name,
        }
    }
}

impl From<SendEncryptionType> for bitwarden_api_api::models::SendEncryptionType {
    fn from(t: SendEncryptionType) -> Self {
        match t {
            SendEncryptionType::V1 => bitwarden_api_api::models::SendEncryptionType::V1,
        }
    }
}

impl TryFrom<bitwarden_api_api::models::SendEncryptionType> for SendEncryptionType {
    type Error = bitwarden_core::MissingFieldError;

    fn try_from(value: bitwarden_api_api::models::SendEncryptionType) -> Result<Self, Self::Error> {
        Ok(match value {
            bitwarden_api_api::models::SendEncryptionType::V1 => SendEncryptionType::V1,
            bitwarden_api_api::models::SendEncryptionType::__Unknown(_) => {
                return Err(bitwarden_core::MissingFieldError("encryption_version"));
            }
        })
    }
}

impl From<SendText> for SendTextModel {
    fn from(text: SendText) -> Self {
        SendTextModel {
            text: text.text.map(|text| text.to_string()),
            hidden: Some(text.hidden),
        }
    }
}

impl TryFrom<SendFileModel> for SendFile {
    type Error = SendParseError;

    fn try_from(file: SendFileModel) -> Result<Self, Self::Error> {
        Ok(SendFile {
            id: file.id,
            file_name: require!(file.file_name).parse()?,
            size: file.size.map(|v| v.to_string()),
            size_name: file.size_name,
        })
    }
}

impl TryFrom<SendTextModel> for SendText {
    type Error = SendParseError;

    fn try_from(text: SendTextModel) -> Result<Self, Self::Error> {
        Ok(SendText {
            text: EncString::try_from_optional(text.text)?,
            hidden: text.hidden.unwrap_or(false),
        })
    }
}

impl TryFrom<SendDataModel> for SendItem {
    type Error = SendParseError;

    fn try_from(data: SendDataModel) -> Result<Self, Self::Error> {
        let Some(sealed) = data.data else {
            return Err(SendParseError::DeserializationFailure(
                SendItemDeserializationFailureError,
            ));
        };

        Ok(SendItem {
            encryption_version: SendEncryptionType::try_from(
                data.encryption_version
                    .unwrap_or(DEFAULT_SEND_ENCRYPTION.into()),
            )?,
            data: sealed,
            metadata: SendItemMetadata {
                item_id: CipherId::new(data.metadata.item_id),
            },
        })
    }
}

impl From<SendItem> for SendDataModel {
    fn from(item: SendItem) -> Self {
        SendDataModel {
            encryption_version: Some(item.encryption_version.into()),
            data: Some(item.data),
            metadata: Box::new(SendItemMetadataModel {
                item_id: item.metadata.item_id.into(),
            }),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use bitwarden_api_api::models::SendItemMetadataModel;
    use bitwarden_core::key_management::create_test_crypto_with_user_key;
    use bitwarden_crypto::SymmetricCryptoKey;
    use bitwarden_vault::{
        CipherRepromptType, CipherType, FieldType, FieldView, LoginView, PasswordHistoryView,
    };

    use super::*;

    const TEST_USER_KEY: &str =
        "bYCsk857hl8QJJtxyRK65tjUrbxKC4aDifJpsml+NIv4W9cVgFvi3qVD+yJTUU2T4UwNKWYtt9pqWf7Q+2WCCg==";
    const TEST_SEND_KEY: &str = "2.KLv/j0V4Ebs0dwyPdtt4vw==|jcrFuNYN1Qb3onBlwvtxUV/KpdnR1LPRL4EsCoXNAt4=|gHSywGy4Rj/RsCIZFwze4s2AACYKBtqDXTrQXjkgtIE=";
    const TEST_SEND_KEY_B64: &str = "Pgui0FK85cNhBGWHAlBHBw";
    pub(crate) const TEST_ITEM_ID: &str = "5d4fbf2b-7a36-4b3c-9f2e-1a6d8c0e9b71";

    /// Item Send `data`, sealed under the send key of [`TEST_SEND_KEY`]. Decrypts to
    /// [`item_send_cipher_view`].
    pub(crate) const TEST_VECTOR_ITEM_SEND_DATA: &str = "{\"format_version\":1,\"wrapped_cek\":\"2.e/m5UvBFEh4JEHYgnAVONQ==|Cl7wnKMdT9NxeisUg1Xx3OmOyZr7Z77luoLPCBxuo1EVAjf69q3yaFO25InB8swQgHdKgz/PVqtX6JmmbR4xu2PKZtNFNmRRUVnX5BWvvjE=|+PW2Knoda9s1qVKMAEcXDsw5ij/wUZ/GfR9xVDnpPSw=\",\"envelope\":\"g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUCSl5i37B6J7uBZ8Ge91nw86AAE4gQI6AAE4gAGhBUxDZ7isjgG0Zt2UEERZATT9Jcf0kWC5y8qsWWn4iNEv9kbjf1jPeolS0FdxBu4y11Yez9MT1cPaJ8hxCjRztX5VgGzEKMnOcc491fwZXQByT0M9MLDDpJD3HDOOCzQ2gdk7VZktEmc8nhZoAGnZP0GmeoJh/my3WDukSsa2vOiOLE2KGIfF8OHa7nwXds9Z1aIhlavFSNAiqDWAdOk65OhqrvE0BPN7WdW7+NbuviPiEKa3wbCIhmjfQI1nW5simSqTMx4/ikLCqH2F3gLt4nk0SJ3KAbbQA3ENWMFef8s+m5uNWPIsALXeauC5X8XwvhOI2a1XNldR2r9LCEgg0vqzi+yCLVZpfKRQVFIfBmRwBtBObo1hFLBgbCkH8hXsX/eeU9qhL8oskb7s6HCGX0IGXoPzBLkUJH2IohWh3FMYVPd4Yw==\"}";

    /// Cipher content of the Item Send test vector. Metadata matches what
    /// `unseal_blob_for_item_sends` defaults; the id comes from the Send metadata.
    fn item_send_cipher_view() -> CipherView {
        CipherView {
            id: TEST_ITEM_ID.parse().ok(),
            organization_id: None,
            folder_id: None,
            collection_ids: Vec::new(),
            key: None,
            name: "Item Send".to_string(),
            notes: Some("Item Send notes".to_string()),
            r#type: CipherType::Login,
            login: Some(LoginView {
                username: Some("user@example.com".to_string()),
                password: Some("hunter2".to_string()),
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
            bank_account: None,
            drivers_license: None,
            passport: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: false,
            edit: false,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            attachment_decryption_failures: None,
            fields: Some(vec![FieldView {
                name: Some("field".to_string()),
                value: Some("value".to_string()),
                r#type: FieldType::Text,
                linked_id: None,
            }]),
            password_history: Some(vec![PasswordHistoryView {
                password: "old-password".to_string(),
                last_used_date: "2024-01-01T00:00:00Z".parse().unwrap(),
            }]),
            creation_date: Default::default(),
            deleted_date: None,
            revision_date: Default::default(),
            archived_date: None,
            partial: false,
        }
    }

    fn item_send_view() -> SendView {
        SendView {
            id: "3d80dd72-2d14-4f26-812c-b0f0018aa144".parse().ok(),
            access_id: Some("ct2APRQtJk-BLLDwAYqhRA".to_owned()),
            name: "Test".to_string(),
            notes: None,
            key: Some(TEST_SEND_KEY_B64.to_owned()),
            new_password: None,
            has_password: false,
            r#type: SendType::Item,
            file: None,
            text: None,
            data: Some(SendItemView {
                data: item_send_cipher_view(),
            }),
            max_access_count: None,
            access_count: 0,
            disabled: false,
            hide_email: false,
            revision_date: "2024-01-07T23:56:48.207363Z".parse().unwrap(),
            deletion_date: "2024-01-14T23:56:48Z".parse().unwrap(),
            expiration_date: None,
            emails: Vec::new(),
            auth_type: AuthType::None,
        }
    }

    #[test]
    #[ignore = "Generates test vectors; run manually"]
    fn generate_item_send_test_vector() {
        let user_key: SymmetricCryptoKey = TEST_USER_KEY.to_string().try_into().unwrap();
        let crypto = create_test_crypto_with_user_key(user_key);
        let send: Send = crypto.encrypt(item_send_view()).unwrap();
        println!(
            "pub(crate) const TEST_VECTOR_ITEM_SEND_DATA: &str = {:?};",
            send.data.unwrap().data
        );
    }

    #[test]
    fn test_item_send_test_vector() {
        let user_key: SymmetricCryptoKey = TEST_USER_KEY.to_string().try_into().unwrap();
        let crypto = create_test_crypto_with_user_key(user_key);

        // Parse the wire model as received from the server.
        let item = SendItem::try_from(SendDataModel {
            encryption_version: Some(SendEncryptionType::V1.into()),
            data: Some(TEST_VECTOR_ITEM_SEND_DATA.to_string()),
            metadata: Box::new(SendItemMetadataModel {
                item_id: TEST_ITEM_ID.parse().unwrap(),
            }),
        })
        .unwrap();
        let send = Send {
            id: "3d80dd72-2d14-4f26-812c-b0f0018aa144".parse().ok(),
            access_id: Some("ct2APRQtJk-BLLDwAYqhRA".to_owned()),
            r#type: SendType::Item,
            name: "2.STIyTrfDZN/JXNDN9zNEMw==|NDLum8BHZpPNYhJo9ggSkg==|UCsCLlBO3QzdPwvMAWs2VVwuE6xwOx/vxOooPObqnEw=".parse()
                .unwrap(),
            notes: None,
            file: None,
            text: None,
            data: Some(item),
            key: TEST_SEND_KEY.parse().unwrap(),
            max_access_count: None,
            access_count: 0,
            password: None,
            disabled: false,
            revision_date: "2024-01-07T23:56:48.207363Z".parse().unwrap(),
            expiration_date: None,
            deletion_date: "2024-01-14T23:56:48Z".parse().unwrap(),
            hide_email: false,
            emails: None,
            auth_type: AuthType::None,
        };

        let view: SendView = crypto.decrypt(&send).unwrap();

        assert_eq!(view, item_send_view());
    }

    #[test]
    fn test_item_send_encrypt_round_trip() {
        let user_key: SymmetricCryptoKey = TEST_USER_KEY.to_string().try_into().unwrap();
        let crypto = create_test_crypto_with_user_key(user_key);

        let send: Send = crypto.encrypt(item_send_view()).unwrap();
        let item = send.data.as_ref().unwrap();
        // The wire data is the sealed blob itself, not a serialized `Cipher`.
        assert!(serde_json::from_str::<bitwarden_vault::Cipher>(&item.data).is_err());

        let view: SendView = crypto.decrypt(&send).unwrap();
        assert_eq!(view, item_send_view());
    }

    #[test]
    fn test_item_send_metadata_round_trip() {
        let user_key: SymmetricCryptoKey = TEST_USER_KEY.to_string().try_into().unwrap();
        let crypto = create_test_crypto_with_user_key(user_key);

        // The item id travels as metadata next to the sealed blob.
        let send: Send = crypto.encrypt(item_send_view()).unwrap();
        let item = send.data.as_ref().unwrap();
        assert_eq!(
            item.metadata,
            SendItemMetadata {
                item_id: TEST_ITEM_ID.parse().unwrap()
            }
        );

        let decrypted: SendView = crypto.decrypt(&send).unwrap();
        assert_eq!(decrypted, item_send_view());
    }

    #[test]
    fn test_item_send_encrypt_requires_item_id() {
        let user_key: SymmetricCryptoKey = TEST_USER_KEY.to_string().try_into().unwrap();
        let crypto = create_test_crypto_with_user_key(user_key);

        let mut view = item_send_view();
        view.data.as_mut().unwrap().data.id = None;

        let result: Result<Send, _> = crypto.encrypt(view);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_send_key() {
        // Initialize user encryption with some test data
        let user_key: SymmetricCryptoKey = "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==".to_string().try_into().unwrap();
        let crypto = create_test_crypto_with_user_key(user_key);
        let mut ctx = crypto.context();

        let send_key = "2.+1KUfOX8A83Xkwk1bumo/w==|Nczvv+DTkeP466cP/wMDnGK6W9zEIg5iHLhcuQG6s+M=|SZGsfuIAIaGZ7/kzygaVUau3LeOvJUlolENBOU+LX7g="
            .parse()
            .unwrap();

        // Get the send key
        let send_key = Send::get_key(&mut ctx, &send_key, SymmetricKeySlotId::User).unwrap();
        #[allow(deprecated)]
        let send_key = ctx.dangerous_get_symmetric_key(send_key).unwrap();
        let send_key_b64 = send_key.to_base64();
        assert_eq!(
            send_key_b64.to_string(),
            "IR9ImHGm6rRuIjiN7csj94bcZR5WYTJj5GtNfx33zm6tJCHUl+QZlpNPba8g2yn70KnOHsAODLcR0um6E3MAlg=="
        );
    }

    #[test]
    pub fn test_decrypt() {
        let user_key: SymmetricCryptoKey = "bYCsk857hl8QJJtxyRK65tjUrbxKC4aDifJpsml+NIv4W9cVgFvi3qVD+yJTUU2T4UwNKWYtt9pqWf7Q+2WCCg==".to_string().try_into().unwrap();
        let crypto = create_test_crypto_with_user_key(user_key);

        let send = Send {
            id: "3d80dd72-2d14-4f26-812c-b0f0018aa144".parse().ok(),
            access_id: Some("ct2APRQtJk-BLLDwAYqhRA".to_owned()),
            r#type: SendType::Text,
            name: "2.STIyTrfDZN/JXNDN9zNEMw==|NDLum8BHZpPNYhJo9ggSkg==|UCsCLlBO3QzdPwvMAWs2VVwuE6xwOx/vxOooPObqnEw=".parse()
                .unwrap(),
            notes: None,
            file: None,
            text: Some(SendText {
                text: "2.2VPyLzk1tMLug0X3x7RkaQ==|mrMt9vbZsCJhJIj4eebKyg==|aZ7JeyndytEMR1+uEBupEvaZuUE69D/ejhfdJL8oKq0=".parse().ok(),
                hidden: false,
            }),
            data: None,
            key: "2.KLv/j0V4Ebs0dwyPdtt4vw==|jcrFuNYN1Qb3onBlwvtxUV/KpdnR1LPRL4EsCoXNAt4=|gHSywGy4Rj/RsCIZFwze4s2AACYKBtqDXTrQXjkgtIE=".parse().unwrap(),
            max_access_count: None,
            access_count: 0,
            password: None,
            disabled: false,
            revision_date: "2024-01-07T23:56:48.207363Z".parse().unwrap(),
            expiration_date: None,
            deletion_date: "2024-01-14T23:56:48Z".parse().unwrap(),
            hide_email: false,
            emails: None,
            auth_type: AuthType::None,
        };

        let view: SendView = crypto.decrypt(&send).unwrap();

        let expected = SendView {
            id: "3d80dd72-2d14-4f26-812c-b0f0018aa144".parse().ok(),
            access_id: Some("ct2APRQtJk-BLLDwAYqhRA".to_owned()),
            name: "Test".to_string(),
            notes: None,
            key: Some("Pgui0FK85cNhBGWHAlBHBw".to_owned()),
            new_password: None,
            has_password: false,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("This is a test".to_owned()),
                hidden: false,
            }),
            data: None,
            max_access_count: None,
            access_count: 0,
            disabled: false,
            hide_email: false,
            revision_date: "2024-01-07T23:56:48.207363Z".parse().unwrap(),
            deletion_date: "2024-01-14T23:56:48Z".parse().unwrap(),
            expiration_date: None,
            emails: Vec::new(),
            auth_type: AuthType::None,
        };

        assert_eq!(view, expected);
    }

    #[test]
    pub fn test_encrypt() {
        let user_key: SymmetricCryptoKey = "bYCsk857hl8QJJtxyRK65tjUrbxKC4aDifJpsml+NIv4W9cVgFvi3qVD+yJTUU2T4UwNKWYtt9pqWf7Q+2WCCg==".to_string().try_into().unwrap();
        let crypto = create_test_crypto_with_user_key(user_key);

        let view = SendView {
            id: "3d80dd72-2d14-4f26-812c-b0f0018aa144".parse().ok(),
            access_id: Some("ct2APRQtJk-BLLDwAYqhRA".to_owned()),
            name: "Test".to_string(),
            notes: None,
            key: Some("Pgui0FK85cNhBGWHAlBHBw".to_owned()),
            new_password: None,
            has_password: false,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("This is a test".to_owned()),
                hidden: false,
            }),
            data: None,
            max_access_count: None,
            access_count: 0,
            disabled: false,
            hide_email: false,
            revision_date: "2024-01-07T23:56:48.207363Z".parse().unwrap(),
            deletion_date: "2024-01-14T23:56:48Z".parse().unwrap(),
            expiration_date: None,
            emails: Vec::new(),
            auth_type: AuthType::None,
        };

        // Re-encrypt and decrypt again to ensure encrypt works
        let v: SendView = crypto
            .decrypt(&crypto.encrypt(view.clone()).unwrap())
            .unwrap();
        assert_eq!(v, view);
    }

    #[test]
    pub fn test_create() {
        let user_key: SymmetricCryptoKey = "bYCsk857hl8QJJtxyRK65tjUrbxKC4aDifJpsml+NIv4W9cVgFvi3qVD+yJTUU2T4UwNKWYtt9pqWf7Q+2WCCg==".to_string().try_into().unwrap();
        let crypto = create_test_crypto_with_user_key(user_key);

        let view = SendView {
            id: None,
            access_id: Some("ct2APRQtJk-BLLDwAYqhRA".to_owned()),
            name: "Test".to_string(),
            notes: None,
            key: None,
            new_password: None,
            has_password: false,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("This is a test".to_owned()),
                hidden: false,
            }),
            data: None,
            max_access_count: None,
            access_count: 0,
            disabled: false,
            hide_email: false,
            revision_date: "2024-01-07T23:56:48.207363Z".parse().unwrap(),
            deletion_date: "2024-01-14T23:56:48Z".parse().unwrap(),
            expiration_date: None,
            emails: Vec::new(),
            auth_type: AuthType::None,
        };

        // Re-encrypt and decrypt again to ensure encrypt works
        let v: SendView = crypto
            .decrypt(&crypto.encrypt(view.clone()).unwrap())
            .unwrap();

        // Ignore key when comparing
        let t = SendView { key: None, ..v };
        assert_eq!(t, view);
    }

    #[test]
    pub fn test_create_password() {
        let user_key: SymmetricCryptoKey = "bYCsk857hl8QJJtxyRK65tjUrbxKC4aDifJpsml+NIv4W9cVgFvi3qVD+yJTUU2T4UwNKWYtt9pqWf7Q+2WCCg==".to_string().try_into().unwrap();
        let crypto = create_test_crypto_with_user_key(user_key);

        let view = SendView {
            id: None,
            access_id: Some("ct2APRQtJk-BLLDwAYqhRA".to_owned()),
            name: "Test".to_owned(),
            notes: None,
            key: Some("Pgui0FK85cNhBGWHAlBHBw".to_owned()),
            new_password: Some("abc123".to_owned()),
            has_password: false,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("This is a test".to_owned()),
                hidden: false,
            }),
            data: None,
            max_access_count: None,
            access_count: 0,
            disabled: false,
            hide_email: false,
            revision_date: "2024-01-07T23:56:48.207363Z".parse().unwrap(),
            deletion_date: "2024-01-14T23:56:48Z".parse().unwrap(),
            expiration_date: None,
            emails: Vec::new(),
            auth_type: AuthType::Password,
        };

        let send: Send = crypto.encrypt(view).unwrap();

        assert_eq!(
            send.password,
            Some("vTIDfdj3FTDbejmMf+mJWpYdMXsxfeSd1Sma3sjCtiQ=".to_owned())
        );
        assert_eq!(send.auth_type, AuthType::Password);

        let v: SendView = crypto.decrypt(&send).unwrap();
        assert_eq!(v.new_password, None);
        assert!(v.has_password);
        assert_eq!(v.auth_type, AuthType::Password);
    }

    #[test]
    pub fn test_create_email_otp() {
        let user_key: SymmetricCryptoKey = "bYCsk857hl8QJJtxyRK65tjUrbxKC4aDifJpsml+NIv4W9cVgFvi3qVD+yJTUU2T4UwNKWYtt9pqWf7Q+2WCCg==".to_string().try_into().unwrap();
        let crypto = create_test_crypto_with_user_key(user_key);

        let view = SendView {
            id: None,
            access_id: Some("ct2APRQtJk-BLLDwAYqhRA".to_owned()),
            name: "Test".to_owned(),
            notes: None,
            key: Some("Pgui0FK85cNhBGWHAlBHBw".to_owned()),
            new_password: None,
            has_password: false,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("This is a test".to_owned()),
                hidden: false,
            }),
            data: None,
            max_access_count: None,
            access_count: 0,
            disabled: false,
            hide_email: false,
            revision_date: "2024-01-07T23:56:48.207363Z".parse().unwrap(),
            deletion_date: "2024-01-14T23:56:48Z".parse().unwrap(),
            expiration_date: None,
            emails: vec![
                String::from("test1@mail.com"),
                String::from("test2@mail.com"),
            ],
            auth_type: AuthType::Email,
        };

        let send: Send = crypto.encrypt(view.clone()).unwrap();

        // Verify decrypted view matches original prior to encrypting
        let v: SendView = crypto.decrypt(&send).unwrap();

        assert_eq!(v, view);
    }

    #[test]
    fn test_send_into_send_with_id_request_model() {
        let send_id = "3d80dd72-2d14-4f26-812c-b0f0018aa144".parse().unwrap();
        let revision_date = DateTime::parse_from_rfc3339("2024-01-07T23:56:48Z")
            .unwrap()
            .with_timezone(&Utc);
        let deletion_date = DateTime::parse_from_rfc3339("2024-01-14T23:56:48Z")
            .unwrap()
            .with_timezone(&Utc);
        let expiration_date = DateTime::parse_from_rfc3339("2024-01-20T23:56:48Z")
            .unwrap()
            .with_timezone(&Utc);

        let name = "2.STIyTrfDZN/JXNDN9zNEMw==|NDLum8BHZpPNYhJo9ggSkg==|UCsCLlBO3QzdPwvMAWs2VVwuE6xwOx/vxOooPObqnEw=";
        let notes = "2.2VPyLzk1tMLug0X3x7RkaQ==|mrMt9vbZsCJhJIj4eebKyg==|aZ7JeyndytEMR1+uEBupEvaZuUE69D/ejhfdJL8oKq0=";
        let key = "2.KLv/j0V4Ebs0dwyPdtt4vw==|jcrFuNYN1Qb3onBlwvtxUV/KpdnR1LPRL4EsCoXNAt4=|gHSywGy4Rj/RsCIZFwze4s2AACYKBtqDXTrQXjkgtIE=";
        let file_name = "2.+1KUfOX8A83Xkwk1bumo/w==|Nczvv+DTkeP466cP/wMDnGK6W9zEIg5iHLhcuQG6s+M=|SZGsfuIAIaGZ7/kzygaVUau3LeOvJUlolENBOU+LX7g=";
        let text_value = "2.2VPyLzk1tMLug0X3x7RkaQ==|mrMt9vbZsCJhJIj4eebKyg==|aZ7JeyndytEMR1+uEBupEvaZuUE69D/ejhfdJL8oKq0=";

        let send = Send {
            id: Some(SendId::new(send_id)),
            access_id: Some("ct2APRQtJk-BLLDwAYqhRA".to_string()),
            name: name.parse().unwrap(),
            notes: Some(notes.parse().unwrap()),
            key: key.parse().unwrap(),
            password: Some("hash".to_string()),
            r#type: SendType::File,
            file: Some(SendFile {
                id: Some("file-id".to_string()),
                file_name: file_name.parse().unwrap(),
                size: Some("1234".to_string()),
                size_name: Some("1.2 KB".to_string()),
            }),
            text: Some(SendText {
                text: Some(text_value.parse().unwrap()),
                hidden: true,
            }),
            data: None,
            max_access_count: Some(42),
            access_count: 0,
            disabled: true,
            hide_email: true,
            revision_date,
            deletion_date,
            expiration_date: Some(expiration_date),
            emails: Some("test1@mail.com,test2@mail.com".to_string()),
            auth_type: AuthType::Email,
        };

        let model: SendWithIdRequestModel = send.into();

        assert_eq!(model.id, send_id);
        assert_eq!(
            model.r#type,
            Some(bitwarden_api_api::models::SendType::File)
        );
        assert_eq!(
            model.auth_type,
            Some(bitwarden_api_api::models::AuthType::Email)
        );
        assert_eq!(model.file_length, Some(1234));
        assert_eq!(model.name.as_deref(), Some(name));
        assert_eq!(model.notes.as_deref(), Some(notes));
        assert_eq!(model.key, key);
        assert_eq!(model.max_access_count, Some(42));
        assert_eq!(
            model
                .expiration_date
                .unwrap()
                .parse::<DateTime<Utc>>()
                .unwrap(),
            expiration_date
        );
        assert_eq!(
            model.deletion_date.parse::<DateTime<Utc>>().unwrap(),
            deletion_date
        );
        assert_eq!(model.password.as_deref(), Some("hash"));
        assert_eq!(
            model.emails.as_deref(),
            Some("test1@mail.com,test2@mail.com")
        );
        assert!(model.disabled);
        assert_eq!(model.hide_email, Some(true));

        let file = model.file.unwrap();
        assert_eq!(file.id.as_deref(), Some("file-id"));
        assert_eq!(file.file_name.as_deref(), Some(file_name));
        assert_eq!(file.size.as_deref(), Some("1234"));
        assert_eq!(file.size_name.as_deref(), Some("1.2 KB"));

        let text = model.text.unwrap();
        assert_eq!(text.text.as_deref(), Some(text_value));
        assert_eq!(text.hidden, Some(true));
    }

    #[test]
    fn test_item_send_into_send_with_id_request_model() {
        let send = Send {
            id: "3d80dd72-2d14-4f26-812c-b0f0018aa144".parse().ok(),
            access_id: None,
            r#type: SendType::Item,
            name: "2.STIyTrfDZN/JXNDN9zNEMw==|NDLum8BHZpPNYhJo9ggSkg==|UCsCLlBO3QzdPwvMAWs2VVwuE6xwOx/vxOooPObqnEw=".parse()
                .unwrap(),
            notes: None,
            file: None,
            text: None,
            data: Some(SendItem {
                encryption_version: SendEncryptionType::V1,
                data: TEST_VECTOR_ITEM_SEND_DATA.to_string(),
                metadata: SendItemMetadata {
                    item_id: TEST_ITEM_ID.parse().unwrap(),
                },
            }),
            key: TEST_SEND_KEY.parse().unwrap(),
            max_access_count: None,
            access_count: 0,
            password: None,
            disabled: false,
            revision_date: "2024-01-07T23:56:48Z".parse().unwrap(),
            expiration_date: None,
            deletion_date: "2024-01-14T23:56:48Z".parse().unwrap(),
            hide_email: false,
            emails: None,
            auth_type: AuthType::None,
        };

        let model: SendWithIdRequestModel = send.into();

        // Key rotation sends this model; the server rejects Item Sends without data.
        let data = model.data.expect("Item Send request must carry its data");
        assert_eq!(
            data.encryption_version,
            Some(bitwarden_api_api::models::SendEncryptionType::V1)
        );
        assert_eq!(data.data.as_deref(), Some(TEST_VECTOR_ITEM_SEND_DATA));
        assert_eq!(data.metadata.item_id.to_string(), TEST_ITEM_ID);
    }

    #[test]
    fn auth_data_hashed_password_returns_key_b64_verbatim() {
        // `HashedPassword` is the wire-form contract: the caller supplies the already-
        // derived base64 hash and the SDK must NOT run PBKDF2 again. We assert by
        // checking that the returned password equals the input byte-for-byte, including
        // for inputs that wouldn't be valid base64 (proves no decode/re-encode happens).
        let key_b64 = "pretend-this-is-a-pbkdf2-output==".to_string();
        let auth = SendAuthType::HashedPassword {
            key_b64: key_b64.clone(),
        };

        let (password, emails) = auth.auth_data(b"any-send-key-bytes-here");

        assert_eq!(password, Some(key_b64));
        assert_eq!(emails, None);
    }

    #[test]
    fn auth_data_hashed_and_plaintext_diverge_for_same_input() {
        // Sanity check: passing the same string through `Password` and `HashedPassword`
        // produces different wire outputs, so a mis-routed caller (plaintext into
        // `HashedPassword`) fails loudly server-side rather than silently producing the
        // same hash as the plaintext path would.
        let same_string = "abc123".to_string();
        let send_key = b"send-key-salt-bytes";

        let (plaintext_out, _) = SendAuthType::Password {
            password: same_string.clone(),
        }
        .auth_data(send_key);
        let (hashed_out, _) = SendAuthType::HashedPassword {
            key_b64: same_string,
        }
        .auth_data(send_key);

        assert_ne!(
            plaintext_out, hashed_out,
            "Plaintext path must run PBKDF2; HashedPassword path must not"
        );
    }

    #[test]
    fn auth_type_for_hashed_password_maps_to_password() {
        // Both `Password` and `HashedPassword` produce `authType = Password` on the wire;
        // the server doesn't distinguish.
        assert_eq!(
            SendAuthType::Password {
                password: "p".to_string()
            }
            .auth_type(),
            AuthType::Password,
        );
        assert_eq!(
            SendAuthType::HashedPassword {
                key_b64: "k".to_string()
            }
            .auth_type(),
            AuthType::Password,
        );
    }

    /// Pins the wire shape of `SendAuthType` including the new `HashedPassword` variant
    /// (`"type": "hashedPassword"` under camelCase rename). Same pattern as the existing
    /// regression tests that pin internally-tagged serde enums.
    #[test]
    fn send_auth_type_round_trips_through_json() {
        let cases = [
            (SendAuthType::None, serde_json::json!({"type": "none"})),
            (
                SendAuthType::Password {
                    password: "hunter2".to_string(),
                },
                serde_json::json!({"type": "password", "password": "hunter2"}),
            ),
            (
                SendAuthType::HashedPassword {
                    key_b64: "deadbeef==".to_string(),
                },
                serde_json::json!({"type": "hashedPassword", "keyB64": "deadbeef=="}),
            ),
            (
                SendAuthType::Emails {
                    emails: vec!["a@b.com".to_string()],
                },
                serde_json::json!({"type": "emails", "emails": ["a@b.com"]}),
            ),
        ];
        for (value, expected) in cases {
            let serialized = serde_json::to_value(&value).expect("serialize");
            assert_eq!(serialized, expected, "wire shape mismatch for {value:?}");
            let deserialized: SendAuthType =
                serde_json::from_value(serialized).expect("round-trip");
            assert_eq!(deserialized, value, "round-trip mismatch for {value:?}");
        }
    }

    #[test]
    fn typed_constructors_produce_expected_variants() {
        assert_eq!(
            SendAuthType::from_plaintext_password("hunter2".to_string()),
            SendAuthType::Password {
                password: "hunter2".to_string()
            },
        );
        assert_eq!(
            SendAuthType::from_hashed_password("deadbeef==".to_string()),
            SendAuthType::HashedPassword {
                key_b64: "deadbeef==".to_string()
            },
        );
    }
}
