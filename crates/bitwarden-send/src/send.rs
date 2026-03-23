use bitwarden_api_api::models::{
    SendFileModel, SendResponseModel, SendTextModel, SendWithIdRequestModel,
};
use bitwarden_core::{
    key_management::{KeyIds, SymmetricKeyId},
    require,
};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, Decryptable, EncString, IdentifyKey, KeyStoreContext,
    OctetStreamBytes, PrimitiveEncryptable, generate_random_bytes,
};
use bitwarden_encoding::{B64, B64Url};
use bitwarden_uuid::uuid_newtype;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use uuid::Uuid;
use zeroize::Zeroizing;
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

use crate::SendParseError;
pub const SEND_ITERATIONS: u32 = 100_000;

uuid_newtype!(pub SendId);

/// File-based send content
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendFile {
    pub id: Option<String>,
    pub file_name: EncString,
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

/// The type of Send, either text or file
#[derive(Clone, Copy, Serialize_repr, Deserialize_repr, Debug, PartialEq)]
#[repr(u8)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum SendType {
    /// Text-based send
    Text = 0,
    /// File-based send
    File = 1,
}

/// Indicates the authentication strategy to use when accessing a Send
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum AuthType {
    /// Email-based OTP authentication
    Email = 0,

    /// Password-based authentication
    Password = 1,

    /// No authentication required
    None = 2,
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
    /// Password-based authentication
    Password {
        /// The password required to access the Send
        password: String,
    },
    /// Email-based OTP authentication
    Emails {
        /// List of email addresses that will receive OTP codes
        emails: String,
    },
}

impl SendAuthType {
    /// Returns the AuthType discriminant for this authentication method
    pub fn auth_type(&self) -> AuthType {
        match self {
            SendAuthType::None => AuthType::None,
            SendAuthType::Password { .. } => AuthType::Password,
            SendAuthType::Emails { .. } => AuthType::Email,
        }
    }

    /// Returns the password if this is a Password variant, emails if this is an Emails variant, or
    /// None otherwise
    pub fn auth_data(&self, k: Vec<u8>) -> (Option<String>, Option<String>) {
        match self {
            SendAuthType::Password { password } => {
                let hashed = bitwarden_crypto::pbkdf2(password.as_bytes(), &k, SEND_ITERATIONS);
                (Some(B64::from(hashed.as_slice()).to_string()), None)
            }
            SendAuthType::Emails { emails } => {
                let emails_str = if emails.is_empty() {
                    None
                } else {
                    Some(emails.clone())
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
}

/// Type alias for the tuple returned by SendViewType::into_api_models
type SendApiModels = (
    bitwarden_api_api::models::SendType,
    Option<Box<bitwarden_api_api::models::SendFileModel>>,
    Option<Box<bitwarden_api_api::models::SendTextModel>>,
);

impl CompositeEncryptable<KeyIds, SymmetricKeyId, SendApiModels> for SendViewType {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<SendApiModels, CryptoError> {
        match self {
            SendViewType::File(f) => Ok((
                bitwarden_api_api::models::SendType::File,
                Some(Box::new(bitwarden_api_api::models::SendFileModel {
                    id: f.id.clone(),
                    file_name: Some(f.file_name.encrypt(ctx, key)?.to_string()),
                    size: f.size.as_ref().and_then(|s| s.parse::<i64>().ok()),
                    size_name: f.size_name.clone(),
                })),
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
            )),
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

bitwarden_state::register_repository_item!(Uuid => Send, "Send");

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

    pub max_access_count: Option<u32>,
    pub access_count: u32,
    pub disabled: bool,
    pub hide_email: bool,

    pub revision_date: DateTime<Utc>,
    pub deletion_date: DateTime<Utc>,
    pub expiration_date: Option<DateTime<Utc>>,

    /// Email addresses for OTP authentication.
    /// **Note**: Mutually exclusive with `new_password`. If both are set,
    /// only password authentication will be used.
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
        ctx: &mut KeyStoreContext<KeyIds>,
        send_key: &EncString,
        enc_key: SymmetricKeyId,
    ) -> Result<SymmetricKeyId, CryptoError> {
        let key: Vec<u8> = send_key.decrypt(ctx, enc_key)?;
        Self::derive_shareable_key(ctx, &key)
    }

    pub(crate) fn derive_shareable_key(
        ctx: &mut KeyStoreContext<KeyIds>,
        key: &[u8],
    ) -> Result<SymmetricKeyId, CryptoError> {
        let key = Zeroizing::new(key.try_into().map_err(|_| CryptoError::InvalidKeyLen)?);
        ctx.derive_shareable_key(key, "send", Some("send"))
    }
}

impl IdentifyKey<SymmetricKeyId> for Send {
    fn key_identifier(&self) -> SymmetricKeyId {
        SymmetricKeyId::User
    }
}

impl IdentifyKey<SymmetricKeyId> for SendView {
    fn key_identifier(&self) -> SymmetricKeyId {
        SymmetricKeyId::User
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, SendTextView> for SendText {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<SendTextView, CryptoError> {
        Ok(SendTextView {
            text: self.text.decrypt(ctx, key)?,
            hidden: self.hidden,
        })
    }
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, SendText> for SendTextView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<SendText, CryptoError> {
        Ok(SendText {
            text: self.text.encrypt(ctx, key)?,
            hidden: self.hidden,
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, SendFileView> for SendFile {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<SendFileView, CryptoError> {
        Ok(SendFileView {
            id: self.id.clone(),
            file_name: self.file_name.decrypt(ctx, key)?,
            size: self.size.clone(),
            size_name: self.size_name.clone(),
        })
    }
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, SendFile> for SendFileView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<SendFile, CryptoError> {
        Ok(SendFile {
            id: self.id.clone(),
            file_name: self.file_name.encrypt(ctx, key)?,
            size: self.size.clone(),
            size_name: self.size_name.clone(),
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, SendView> for Send {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
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

impl Decryptable<KeyIds, SymmetricKeyId, SendListView> for Send {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
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

impl CompositeEncryptable<KeyIds, SymmetricKeyId, Send> for SendView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
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
                let key = generate_random_bytes::<[u8; 16]>();
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
            password: self.new_password.as_ref().map(|password| {
                let password = bitwarden_crypto::pbkdf2(password.as_bytes(), &k, SEND_ITERATIONS);
                B64::from(password.as_slice()).to_string()
            }),

            r#type: self.r#type,
            file: self.file.encrypt_composite(ctx, send_key)?,
            text: self.text.encrypt_composite(ctx, send_key)?,

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
            size: file.size.and_then(|size| size.parse::<i64>().ok()),
            size_name: file.size_name,
        }
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

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::create_test_crypto_with_user_key;
    use bitwarden_crypto::SymmetricCryptoKey;

    use super::*;

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
        let send_key = Send::get_key(&mut ctx, &send_key, SymmetricKeyId::User).unwrap();
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
        let send_id = Uuid::parse_str("3d80dd72-2d14-4f26-812c-b0f0018aa144").unwrap();
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
        assert_eq!(file.size, Some(1234));
        assert_eq!(file.size_name.as_deref(), Some("1.2 KB"));

        let text = model.text.unwrap();
        assert_eq!(text.text.as_deref(), Some(text_value));
        assert_eq!(text.hidden, Some(true));
    }
}
