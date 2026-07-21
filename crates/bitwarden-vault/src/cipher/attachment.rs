use bitwarden_api_api::models::CipherAttachmentModel;
use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, Decryptable, EncString, IdentifyKey, KeyStoreContext,
    OctetStreamBytes, PrimitiveEncryptable, SymmetricCryptoKey,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use super::Cipher;
use crate::VaultParseError;

/// Cryptographic material for a new attachment, shared by the upgrade and create paths.
pub(crate) struct AttachmentMaterial {
    /// Raw attachment key, used to encrypt the attachment contents.
    pub(crate) key: SymmetricCryptoKey,
    /// Attachment key wrapped with the cipher key, stored on the attachment record.
    pub(crate) wrapped_key: EncString,
    /// File name encrypted with the cipher key.
    pub(crate) encrypted_file_name: EncString,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct Attachment {
    pub id: Option<String>,
    pub url: Option<String>,
    pub size: Option<String>,
    /// Readable size, ex: "4.2 KB" or "1.43 GB"
    pub size_name: Option<String>,
    pub file_name: Option<EncString>,
    pub key: Option<EncString>,
}

impl From<Attachment> for CipherAttachmentModel {
    fn from(attachment: Attachment) -> Self {
        Self {
            file_name: attachment.file_name.map(|f| f.to_string()),
            key: attachment.key.map(|k| k.to_string()),
        }
    }
}

/// The encryption format an attachment uses, derived from whether it carries its own key.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AttachmentEncryptionVersion {
    /// Legacy v1: contents are encrypted directly with the cipher key; no per-attachment key.
    LegacyNoKeyV1,
    /// V2: a per-attachment key, wrapped by the cipher key, encrypts the contents.
    AttachmentKeyV2,
}

impl Attachment {
    /// Returns the [`AttachmentEncryptionVersion`] this attachment uses.
    pub(crate) fn encryption_version(&self) -> AttachmentEncryptionVersion {
        match self.key {
            Some(_) => AttachmentEncryptionVersion::AttachmentKeyV2,
            None => AttachmentEncryptionVersion::LegacyNoKeyV1,
        }
    }
}

/// The full decrypted view of an attachment, including its cryptographic key.
///
/// Eventually this will be made SDK-internal and a separate `AttachmentView` (without the key) will
/// be exposed to clients. That requires all attachment operations to already live in the SDK, so
/// clients never need to handle the key themselves.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct AttachmentFullView {
    pub id: Option<String>,
    pub url: Option<String>,
    pub size: Option<String>,
    pub size_name: Option<String>,
    pub file_name: Option<String>,
    /// The decrypted per-attachment key that encrypts the attachment contents.
    ///
    /// This is the decrypted key material, consistent with the [`CompositeEncryptable`] contract
    /// that a `*View` holds plaintext. On encryption it is wrapped with the cipher key to produce
    /// [`Attachment::key`]; `None` marks a legacy v1 attachment whose contents are encrypted
    /// directly with the user/organization key.
    pub key: Option<SymmetricCryptoKey>,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AttachmentEncryptResult {
    pub attachment: Attachment,
    pub contents: Vec<u8>,
}

#[allow(missing_docs)]
pub struct AttachmentFile {
    pub cipher: Cipher,
    pub attachment: AttachmentFullView,

    /// There are three different ways attachments are encrypted.
    /// 1. UserKey / OrgKey (Contents) - Legacy
    /// 2. AttachmentKey(Contents) - Pre CipherKey
    /// 3. CipherKey(AttachmentKey(Contents)) - Current
    pub contents: EncString,
}

#[allow(missing_docs)]
pub struct AttachmentFileView<'a> {
    pub cipher: Cipher,
    pub attachment: AttachmentFullView,
    pub contents: &'a [u8],
}

impl IdentifyKey<SymmetricKeySlotId> for AttachmentFileView<'_> {
    fn key_identifier(&self) -> SymmetricKeySlotId {
        self.cipher.key_identifier()
    }
}
impl IdentifyKey<SymmetricKeySlotId> for AttachmentFile {
    fn key_identifier(&self) -> SymmetricKeySlotId {
        self.cipher.key_identifier()
    }
}

impl CompositeEncryptable<KeySlotIds, SymmetricKeySlotId, AttachmentEncryptResult>
    for AttachmentFileView<'_>
{
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<AttachmentEncryptResult, CryptoError> {
        let ciphers_key = Cipher::decrypt_cipher_key(ctx, key, &self.cipher.key)?;

        let mut attachment = self.attachment.clone();

        // Because this is a new attachment, we have to generate a key for it and encrypt the
        // contents with it. The decrypted key is stored on the view; wrapping it with the cipher
        // key is handled by `AttachmentFullView::encrypt_composite` below.
        let attachment_key = ctx.generate_symmetric_key();
        let encrypted_contents =
            OctetStreamBytes::from(self.contents).encrypt(ctx, attachment_key)?;
        #[allow(deprecated)]
        {
            attachment.key = Some(ctx.dangerous_get_symmetric_key(attachment_key)?.clone());
        }

        let contents = encrypted_contents.to_buffer()?;

        // Once we have the encrypted contents, we can set the size of the attachment
        attachment.size = Some(contents.len().to_string());
        attachment.size_name = Some(size_name(contents.len()));

        Ok(AttachmentEncryptResult {
            attachment: attachment.encrypt_composite(ctx, ciphers_key)?,
            contents,
        })
    }
}

fn size_name(size: usize) -> String {
    let units = ["Bytes", "KB", "MB", "GB", "TB"];
    let size = size as f64;
    let unit = (size.ln() / 1024_f64.ln()).floor() as usize;
    let size = size / 1024_f64.powi(unit as i32);

    let size_round = (size * 10.0_f64).round() as usize as f64 / 10.0_f64;
    format!("{} {}", size_round, units[unit])
}

impl Decryptable<KeySlotIds, SymmetricKeySlotId, Vec<u8>> for AttachmentFile {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<Vec<u8>, CryptoError> {
        // Version 2 or 3, `AttachmentKey` or `CipherKey(AttachmentKey)`. The view already carries
        // the decrypted content key (unwrapped when the attachment was decrypted), so register it
        // in the context and decrypt with it directly - the cipher key is not needed here.
        if let Some(attachment_key) = &self.attachment.key {
            let content_key = ctx.add_local_symmetric_key(attachment_key.clone());
            self.contents.decrypt(ctx, content_key).map_err(|e| {
                tracing::warn!(
                    attachment_id = ?self.attachment.id,
                    cipher_id = ?self.cipher.id,
                    error = %e,
                    "Failed to decrypt attachment contents with attachment key (v2/v3)"
                );
                e
            })
        } else {
            // Legacy attachment version 1, use user/org key
            self.contents.decrypt(ctx, key).map_err(|e| {
                tracing::warn!(
                    attachment_id = ?self.attachment.id,
                    cipher_id = ?self.cipher.id,
                    error = %e,
                    "Failed to decrypt attachment contents with user/org key (legacy v1)"
                );
                e
            })
        }
    }
}

impl CompositeEncryptable<KeySlotIds, SymmetricKeySlotId, Attachment> for AttachmentFullView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<Attachment, CryptoError> {
        // Wrap the decrypted attachment key with the cipher key to produce the stored, wrapped
        // key. `None` (legacy v1) stays `None`.
        let wrapped_key = self
            .key
            .as_ref()
            .map(|attachment_key| {
                let key_id = ctx.add_local_symmetric_key(attachment_key.clone());
                ctx.wrap_symmetric_key(key, key_id)
            })
            .transpose()?;

        Ok(Attachment {
            id: self.id.clone(),
            url: self.url.clone(),
            size: self.size.clone(),
            size_name: self.size_name.clone(),
            file_name: self.file_name.encrypt(ctx, key)?,
            key: wrapped_key,
        })
    }
}

impl Decryptable<KeySlotIds, SymmetricKeySlotId, AttachmentFullView> for Attachment {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<AttachmentFullView, CryptoError> {
        // Decrypt the file name or return an error if decryption fails
        let file_name = self.file_name.decrypt(ctx, key)?;

        // Unwrap the stored, wrapped attachment key into its decrypted form for the view. `None`
        // (legacy v1) stays `None`.
        let attachment_key = self
            .key
            .as_ref()
            .map(|wrapped_key| {
                let content_key_id = ctx.unwrap_symmetric_key(key, wrapped_key)?;
                #[allow(deprecated)]
                ctx.dangerous_get_symmetric_key(content_key_id).cloned()
            })
            .transpose()?;

        Ok(AttachmentFullView {
            id: self.id.clone(),
            url: self.url.clone(),
            size: self.size.clone(),
            size_name: self.size_name.clone(),
            file_name,
            key: attachment_key,
        })
    }
}

/// Decrypts a list of attachments, separating successful decryptions from failures.
///
/// Returns a tuple of (successful_attachments, failed_attachments).
pub(crate) fn decrypt_attachments_with_failures(
    attachments: &[Attachment],
    ctx: &mut KeyStoreContext<KeySlotIds>,
    key: SymmetricKeySlotId,
) -> (Vec<AttachmentFullView>, Vec<AttachmentFullView>) {
    let mut successes = Vec::new();
    let mut failures = Vec::new();

    for attachment in attachments {
        match attachment.decrypt(ctx, key) {
            Ok(decrypted) => successes.push(decrypted),
            Err(e) => {
                tracing::warn!(attachment_id = ?attachment.id, error = %e, "Failed to decrypt attachment");
                failures.push(AttachmentFullView {
                    id: attachment.id.clone(),
                    url: attachment.url.clone(),
                    size: attachment.size.clone(),
                    size_name: attachment.size_name.clone(),
                    file_name: None,
                    // The attachment failed to decrypt, so its decrypted key is unavailable.
                    key: None,
                });
            }
        }
    }

    (successes, failures)
}

impl TryFrom<bitwarden_api_api::models::AttachmentResponseModel> for Attachment {
    type Error = VaultParseError;

    fn try_from(
        attachment: bitwarden_api_api::models::AttachmentResponseModel,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            id: attachment.id,
            url: attachment.url,
            size: attachment.size,
            size_name: attachment.size_name,
            file_name: EncString::try_from_optional(attachment.file_name)?,
            key: EncString::try_from_optional(attachment.key)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::{SymmetricKeySlotId, create_test_crypto_with_user_key};
    use bitwarden_crypto::{EncString, SymmetricCryptoKey};
    use bitwarden_encoding::B64;

    use crate::{
        AttachmentFile, AttachmentFileView, AttachmentFullView, Cipher,
        cipher::cipher::{CipherRepromptType, CipherType},
    };

    #[test]
    fn test_size_name_conversions() {
        assert_eq!(super::size_name(0), "0 Bytes");
        assert_eq!(super::size_name(19), "19 Bytes");
        assert_eq!(super::size_name(1024), "1 KB");
        assert_eq!(super::size_name(1570), "1.5 KB");
        assert_eq!(super::size_name(1024 * 1024), "1 MB");
        assert_eq!(super::size_name(1024 * 18999), "18.6 MB");
        assert_eq!(super::size_name(1024 * 1024 * 1024), "1 GB");
        assert_eq!(super::size_name(1024 * 1024 * 1024 * 1024), "1 TB");
    }

    #[test]
    fn test_encrypt_attachment() {
        let user_key: SymmetricCryptoKey = "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==".to_string().try_into().unwrap();
        let key_store = create_test_crypto_with_user_key(user_key);

        let attachment = AttachmentFullView {
            id: None,
            url: None,
            size: Some("100".into()),
            size_name: Some("100 Bytes".into()),
            file_name: Some("Test.txt".into()),
            key: None,
        };

        let contents = b"This is a test file that we will encrypt. It's 100 bytes long, the encrypted version will be longer!";

        let attachment_file = AttachmentFileView {
            cipher: Cipher {
                id: None,
                organization_id: None,
                folder_id: None,
                collection_ids: Vec::new(),
                key: Some("2.Gg8yCM4IIgykCZyq0O4+cA==|GJLBtfvSJTDJh/F7X4cJPkzI6ccnzJm5DYl3yxOW2iUn7DgkkmzoOe61sUhC5dgVdV0kFqsZPcQ0yehlN1DDsFIFtrb4x7LwzJNIkMgxNyg=|1rGkGJ8zcM5o5D0aIIwAyLsjMLrPsP3EWm3CctBO3Fw=".parse().unwrap()),
                name: Some("2.d24xECyEdMZ3MG9s6SrGNw==|XvJlTeu5KJ22M3jKosy6iw==|8xGiQty4X61cDMx6PVqkJfSQ0ZTdA/5L9TpG7QfovoM=".parse().unwrap()),
                notes: None,
                r#type: CipherType::Login,
                login: None,
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
                edit: true,
                permissions: None,
                view_password: true,
                local_data: None,
                attachments: None,
                fields: None,
                password_history: None,
                creation_date: "2023-07-24T12:05:09.466666700Z".parse().unwrap(),
                deleted_date: None,
                revision_date: "2023-07-27T19:28:05.240Z".parse().unwrap(),
                archived_date: None,
                data: None,
            },
            attachment,
            contents: contents.as_slice(),
        };

        let result = key_store.encrypt(attachment_file).unwrap();

        assert_eq!(result.contents.len(), 161);
        assert_eq!(result.attachment.size, Some("161".into()));
        assert_eq!(result.attachment.size_name, Some("161 Bytes".into()));
    }

    #[test]
    fn test_attachment_key() {
        let user_key: SymmetricCryptoKey = "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==".to_string().try_into().unwrap();
        let key_store = create_test_crypto_with_user_key(user_key);

        // The view carries the decrypted content key. Unwrap the stored key (wrapped by the cipher
        // key, which is itself wrapped by the user key) to obtain it.
        let attachment_key = {
            let mut ctx = key_store.context();
            let cipher_key_enc: EncString = "2.Gg8yCM4IIgykCZyq0O4+cA==|GJLBtfvSJTDJh/F7X4cJPkzI6ccnzJm5DYl3yxOW2iUn7DgkkmzoOe61sUhC5dgVdV0kFqsZPcQ0yehlN1DDsFIFtrb4x7LwzJNIkMgxNyg=|1rGkGJ8zcM5o5D0aIIwAyLsjMLrPsP3EWm3CctBO3Fw=".parse().unwrap();
            let cipher_key = ctx
                .unwrap_symmetric_key(SymmetricKeySlotId::User, &cipher_key_enc)
                .unwrap();
            let wrapped_key: EncString = "2.r288/AOSPiaLFkW07EBGBw==|SAmnnCbOLFjX5lnURvoualOetQwuyPc54PAmHDTRrhT0gwO9ailna9U09q9bmBfI5XrjNNEsuXssgzNygRkezoVQvZQggZddOwHB6KQW5EQ=|erIMUJp8j+aTcmhdE50zEX+ipv/eR1sZ7EwULJm/6DY=".parse().unwrap();
            let content_key_id = ctx.unwrap_symmetric_key(cipher_key, &wrapped_key).unwrap();
            #[allow(deprecated)]
            ctx.dangerous_get_symmetric_key(content_key_id)
                .unwrap()
                .clone()
        };

        let attachment = AttachmentFullView {
            id: None,
            url: None,
            size: Some("161".into()),
            size_name: Some("161 Bytes".into()),
            file_name: Some("Test.txt".into()),
            key: Some(attachment_key),
        };

        let cipher  = Cipher {
            id: None,
            organization_id: None,
            folder_id: None,
            collection_ids: Vec::new(),
            key: Some("2.Gg8yCM4IIgykCZyq0O4+cA==|GJLBtfvSJTDJh/F7X4cJPkzI6ccnzJm5DYl3yxOW2iUn7DgkkmzoOe61sUhC5dgVdV0kFqsZPcQ0yehlN1DDsFIFtrb4x7LwzJNIkMgxNyg=|1rGkGJ8zcM5o5D0aIIwAyLsjMLrPsP3EWm3CctBO3Fw=".parse().unwrap()),
            name: Some("2.d24xECyEdMZ3MG9s6SrGNw==|XvJlTeu5KJ22M3jKosy6iw==|8xGiQty4X61cDMx6PVqkJfSQ0ZTdA/5L9TpG7QfovoM=".parse().unwrap()),
            notes: None,
            r#type: CipherType::Login,
            login: None,
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
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            fields: None,
            password_history: None,
            creation_date: "2023-07-24T12:05:09.466666700Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2023-07-27T19:28:05.240Z".parse().unwrap(),
            archived_date: None,
            data: None,
        };

        let enc_file = B64::try_from("Ao00qr1xLsV+ZNQpYZ/UwEwOWo3hheKwCYcOGIbsorZ6JIG2vLWfWEXCVqP0hDuzRvmx8otApNZr8pJYLNwCe1aQ+ySHQYGkdubFjoMojulMbQ959Y4SJ6Its/EnVvpbDnxpXTDpbutDxyhxfq1P3lstL2G9rObJRrxiwdGlRGu1h94UA1fCCkIUQux5LcqUee6W4MyQmRnsUziH8gGzmtI=").unwrap();
        let original = B64::try_from("rMweTemxOL9D0iWWfRxiY3enxiZ5IrwWD6ef2apGO6MvgdGhy2fpwmATmn7BpSj9lRumddLLXm7u8zSp6hnXt1hS71YDNh78LjGKGhGL4sbg8uNnpa/I6GK/83jzqGYN7+ESbg==").unwrap();

        let dec = key_store
            .decrypt(&AttachmentFile {
                cipher,
                attachment,
                contents: EncString::from_buffer(enc_file.as_bytes()).unwrap(),
            })
            .unwrap();

        assert_eq!(dec, original.as_bytes());
    }

    #[test]
    fn test_attachment_without_key() {
        let user_key: SymmetricCryptoKey = "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==".to_string().try_into().unwrap();
        let key_store = create_test_crypto_with_user_key(user_key);

        let attachment = AttachmentFullView {
            id: None,
            url: None,
            size: Some("161".into()),
            size_name: Some("161 Bytes".into()),
            file_name: Some("Test.txt".into()),
            key: None,
        };

        let cipher  = Cipher {
            id: None,
            organization_id: None,
            folder_id: None,
            collection_ids: Vec::new(),
            key: None,
            name: Some("2.d24xECyEdMZ3MG9s6SrGNw==|XvJlTeu5KJ22M3jKosy6iw==|8xGiQty4X61cDMx6PVqkJfSQ0ZTdA/5L9TpG7QfovoM=".parse().unwrap()),
            notes: None,
            r#type: CipherType::Login,
            login: None,
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
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            fields: None,
            password_history: None,
            creation_date: "2023-07-24T12:05:09.466666700Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2023-07-27T19:28:05.240Z".parse().unwrap(),
            archived_date: None,
            data: None,
        };

        let enc_file = B64::try_from("AsQLXOBHrJ8porroTUlPxeJOm9XID7LL9D2+KwYATXEpR1EFjLBpcCvMmnqcnYLXIEefe9TCeY4Us50ux43kRSpvdB7YkjxDKV0O1/y6tB7qC4vvv9J9+O/uDEnMx/9yXuEhAW/LA/TsU/WAgxkOM0uTvm8JdD9LUR1z9Ql7zOWycMVzkvGsk2KBNcqAdrotS5FlDftZOXyU8pWecNeyA/w=").unwrap();
        let original = B64::try_from("rMweTemxOL9D0iWWfRxiY3enxiZ5IrwWD6ef2apGO6MvgdGhy2fpwmATmn7BpSj9lRumddLLXm7u8zSp6hnXt1hS71YDNh78LjGKGhGL4sbg8uNnpa/I6GK/83jzqGYN7+ESbg==").unwrap();

        let dec = key_store
            .decrypt(&AttachmentFile {
                cipher,
                attachment,
                contents: EncString::from_buffer(enc_file.as_bytes()).unwrap(),
            })
            .unwrap();

        assert_eq!(dec, original.as_bytes());
    }
}
