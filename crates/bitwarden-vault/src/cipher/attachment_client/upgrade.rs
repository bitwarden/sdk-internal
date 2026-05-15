use bitwarden_core::{ApiError, MissingFieldError, key_management::KeySlotIds};
use bitwarden_crypto::{EncString, IdentifyKey, KeyStore, PrimitiveEncryptable};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError, RepositoryOption};
use chrono::SecondsFormat;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

#[cfg(feature = "wasm")]
use super::io::{AttachmentByteReader, AttachmentByteWriter, read_chunk};
use super::{
    create::{
        CipherCreateAttachmentError, CreateAttachmentRequest, FileUploadType, create_attachment,
    },
    download_url::CipherGetAttachmentDownloadUrlError,
};
use crate::{
    AttachmentsClient, Cipher, CipherError, CipherId, CipherView, DecryptError, EncryptError,
    VaultParseError,
};

/// Errors returned from preparing an attachment upgrade.
#[allow(missing_docs, dead_code)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CipherPrepareAttachmentUpgradeError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    #[error(transparent)]
    Decrypt(#[from] DecryptError),
    #[error(transparent)]
    Encrypt(#[from] EncryptError),
    #[error(transparent)]
    Cipher(#[from] CipherError),
    #[error(transparent)]
    GetDownloadUrl(#[from] CipherGetAttachmentDownloadUrlError),
    #[error(transparent)]
    CreateAttachment(#[from] CipherCreateAttachmentError),
    #[error("Cipher or attachment not found")]
    NotFound,
    #[error("Attachment already has a key (no upgrade needed)")]
    AlreadyUpgraded,
    #[error("Streaming I/O with the host failed")]
    StreamIo,
    #[error("Legacy attachment header is invalid or has unexpected encryption type")]
    InvalidLegacyHeader,
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for CipherPrepareAttachmentUpgradeError {
    fn from(value: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(value.into())
    }
}

/// Result of streaming a legacy attachment through the upgrade pipeline. The body bytes
/// were pushed to the caller via the [`AttachmentByteWriter`](super::io::AttachmentByteWriter);
/// the caller composes `encType (0x02) || iv || mac || <body>` and POSTs it to
/// [`Self::upload_url`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct AttachmentUpgrade {
    /// Server-assigned ID of the new attachment.
    pub attachment_id: String,
    /// URL the caller POSTs the assembled ciphertext to.
    pub upload_url: String,
    /// Upload transport — `Direct` (Bitwarden server) or `Azure` (presigned blob URL).
    pub file_upload_type: FileUploadType,
    /// EncString-format encrypted file name.
    pub encrypted_file_name: String,
    /// 16-byte AES-CBC IV.
    #[cfg_attr(feature = "wasm", serde(with = "serde_bytes"))]
    #[cfg_attr(feature = "wasm", tsify(type = "Uint8Array"))]
    pub iv: Vec<u8>,
    /// 32-byte HMAC-SHA256 tag over IV + ciphertext.
    #[cfg_attr(feature = "wasm", serde(with = "serde_bytes"))]
    #[cfg_attr(feature = "wasm", tsify(type = "Uint8Array"))]
    pub mac: Vec<u8>,
}

#[cfg(any(feature = "wasm", test))]
async fn lookup_upgrade_target<R: Repository<Cipher> + ?Sized>(
    cipher_id: CipherId,
    attachment_id: &str,
    repository: &R,
    key_store: &KeyStore<KeySlotIds>,
) -> Result<(Cipher, String), CipherPrepareAttachmentUpgradeError> {
    let cipher = repository
        .get(cipher_id)
        .await?
        .ok_or(CipherPrepareAttachmentUpgradeError::NotFound)?;

    let attachment = cipher
        .attachments
        .as_ref()
        .and_then(|atts| atts.iter().find(|a| a.id.as_deref() == Some(attachment_id)))
        .ok_or(CipherPrepareAttachmentUpgradeError::NotFound)?;

    if attachment.key.is_some() {
        return Err(CipherPrepareAttachmentUpgradeError::AlreadyUpgraded);
    }

    let cipher_view: CipherView = key_store.decrypt(&cipher).map_err(DecryptError::from)?;
    let file_name = cipher_view
        .attachments
        .as_ref()
        .and_then(|atts| atts.iter().find(|a| a.id.as_deref() == Some(attachment_id)))
        .and_then(|av| av.file_name.clone())
        .ok_or(MissingFieldError("file_name"))?;

    Ok((cipher, file_name))
}

/// Prepares a legacy attachment for upgrade to the per-attachment-key format using a
/// chunked streaming pipeline. The host feeds the entire downloaded body — including
/// the `encType (1) || IV (16) || MAC (32)` header — to `reader`; the SDK parses the
/// 49-byte header internally and pushes re-encrypted body chunks to `writer`.
///
/// **Tentative-write contract:** the legacy HMAC is verified only at end-of-stream, so
/// bytes passed to `writer.write(...)` are unauthenticated until this resolves `Ok`. On
/// `Err`, hosts MUST drop the bytes already received (do not upload, persist, or display
/// them).
///
/// WASM heap usage is bounded by chunk size — the streaming primitives never hold the
/// full payload in linear memory.
#[cfg(feature = "wasm")]
pub async fn prepare_attachment_upgrade<R: Repository<Cipher> + ?Sized>(
    cipher_id: CipherId,
    attachment_id: &str,
    reader: &AttachmentByteReader,
    writer: &AttachmentByteWriter,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    key_store: &KeyStore<KeySlotIds>,
) -> Result<AttachmentUpgrade, CipherPrepareAttachmentUpgradeError> {
    let (cipher, decrypted_file_name) =
        lookup_upgrade_target(cipher_id, attachment_id, repository, key_store).await?;

    let LegacyHeader {
        iv: legacy_iv,
        mac: legacy_mac,
        leftover,
    } = read_legacy_header(reader).await?;

    let UpgradeStreamingState {
        decryptor,
        encryptor,
        wrapped_attachment_key,
        encrypted_file_name,
    } = derive_streaming_state(&cipher, &decrypted_file_name, &legacy_iv, key_store)?;

    let UpgradeStreamOutput {
        size: output_size,
        iv,
        mac,
    } = stream_reencrypt_payload(reader, writer, decryptor, encryptor, &legacy_mac, leftover)
        .await?;

    // encType (1) || IV (16) || MAC (32) — the header the caller prepends before upload.
    const ENCSTRING_HEADER_BYTES: usize = 1 + 16 + 32;
    let request = CreateAttachmentRequest {
        key: wrapped_attachment_key.to_string(),
        file_name: encrypted_file_name.to_string(),
        file_size: (output_size + ENCSTRING_HEADER_BYTES) as i64,
        last_known_revision_date: cipher
            .revision_date
            .to_rfc3339_opts(SecondsFormat::Millis, true),
        as_admin: false,
    };
    let created = create_attachment(cipher_id, request, api_client, repository).await?;

    Ok(AttachmentUpgrade {
        attachment_id: created.attachment_id,
        upload_url: created.upload_url,
        file_upload_type: created.file_upload_type,
        encrypted_file_name: encrypted_file_name.to_string(),
        iv: iv.to_vec(),
        mac: mac.to_vec(),
    })
}

#[cfg(feature = "wasm")]
struct UpgradeStreamingState {
    decryptor: bitwarden_crypto::safe::StreamingAttachmentDecryptor,
    encryptor: bitwarden_crypto::safe::StreamingAttachmentEncryptor,
    wrapped_attachment_key: EncString,
    encrypted_file_name: EncString,
}

/// Scoped synchronously so the [`KeyStoreContext`] isn't held across the streaming I/O
/// loop's await points.
#[cfg(feature = "wasm")]
fn derive_streaming_state(
    cipher: &Cipher,
    decrypted_file_name: &str,
    legacy_iv: &[u8; 16],
    key_store: &KeyStore<KeySlotIds>,
) -> Result<UpgradeStreamingState, CipherPrepareAttachmentUpgradeError> {
    let mut ctx = key_store.context();
    let identity_key_slot = cipher.key_identifier();
    let cipher_key_slot = Cipher::decrypt_cipher_key(&mut ctx, identity_key_slot, &cipher.key)
        .map_err(DecryptError::from)?;
    // v1 attachments are encrypted with the cipher's identity (user/org) key — see the
    // legacy branch in `AttachmentFile::decrypt`. This is independent of whether the
    // cipher has since been migrated to carry its own `cipher.key`, since the rewrap
    // step skips attachments with no `attachment.key`.
    let legacy_key_slot = identity_key_slot;
    let new_attachment_key_slot = ctx.generate_symmetric_key();

    let wrapped_attachment_key = ctx
        .wrap_symmetric_key(cipher_key_slot, new_attachment_key_slot)
        .map_err(EncryptError::from)?;
    let encrypted_file_name = decrypted_file_name
        .encrypt(&mut ctx, cipher_key_slot)
        .map_err(EncryptError::from)?;

    let decryptor = ctx
        .streaming_decrypt_aes_cbc_hmac(legacy_key_slot, legacy_iv)
        .map_err(DecryptError::from)?;
    let encryptor = ctx
        .streaming_encrypt_aes_cbc_hmac(new_attachment_key_slot)
        .map_err(EncryptError::from)?;

    Ok(UpgradeStreamingState {
        decryptor,
        encryptor,
        wrapped_attachment_key,
        encrypted_file_name,
    })
}

#[cfg(feature = "wasm")]
struct UpgradeStreamOutput {
    size: usize,
    iv: [u8; 16],
    mac: [u8; 32],
}

/// Legacy attachment wire format: `encType (1) || IV (16) || MAC (32)` then payload.
#[cfg(feature = "wasm")]
const LEGACY_HEADER_BYTES: usize = 1 + 16 + 32;
/// `EncString::Aes256Cbc_HmacSha256_B64` — the only encryption type the upgrade flow accepts.
#[cfg(feature = "wasm")]
const LEGACY_ATTACHMENT_ENC_TYPE: u8 = 2;

#[cfg(feature = "wasm")]
struct LegacyHeader {
    iv: [u8; 16],
    mac: [u8; 32],
    /// Payload bytes that arrived in the same chunk as the header; must be fed to the
    /// decryptor before any further reads.
    leftover: Vec<u8>,
}

#[cfg(feature = "wasm")]
async fn read_legacy_header(
    reader: &AttachmentByteReader,
) -> Result<LegacyHeader, CipherPrepareAttachmentUpgradeError> {
    let mut buf: Vec<u8> = Vec::with_capacity(LEGACY_HEADER_BYTES);

    while buf.len() < LEGACY_HEADER_BYTES {
        let chunk = read_chunk(reader)
            .await
            .map_err(|_| CipherPrepareAttachmentUpgradeError::StreamIo)?;
        match chunk {
            None => return Err(CipherPrepareAttachmentUpgradeError::InvalidLegacyHeader),
            Some(bytes) => buf.extend_from_slice(&bytes),
        }
    }

    if buf[0] != LEGACY_ATTACHMENT_ENC_TYPE {
        return Err(CipherPrepareAttachmentUpgradeError::InvalidLegacyHeader);
    }
    let iv: [u8; 16] = buf[1..17].try_into().expect("slice of length 16");
    let mac: [u8; 32] = buf[17..49].try_into().expect("slice of length 32");
    let leftover = buf.split_off(LEGACY_HEADER_BYTES);

    Ok(LegacyHeader { iv, mac, leftover })
}

/// Pumps ciphertext through decrypt → re-encrypt, writing to `writer`. `initial` is
/// payload bytes that arrived alongside the header. The legacy HMAC is verified at
/// end-of-stream, so writes are only authenticated once this returns `Ok`.
#[cfg(feature = "wasm")]
async fn stream_reencrypt_payload(
    reader: &AttachmentByteReader,
    writer: &AttachmentByteWriter,
    mut decryptor: bitwarden_crypto::safe::StreamingAttachmentDecryptor,
    mut encryptor: bitwarden_crypto::safe::StreamingAttachmentEncryptor,
    legacy_mac: &[u8; 32],
    initial: Vec<u8>,
) -> Result<UpgradeStreamOutput, CipherPrepareAttachmentUpgradeError> {
    let mut size: usize = 0;

    let mut emit = async |bytes: &[u8]| -> Result<(), CipherPrepareAttachmentUpgradeError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let view = js_sys::Uint8Array::from(bytes);
        writer
            .write(view)
            .await
            .map_err(|_| CipherPrepareAttachmentUpgradeError::StreamIo)?;
        size += bytes.len();
        Ok(())
    };

    if !initial.is_empty() {
        let cleartext = decryptor.update(&initial);
        if !cleartext.is_empty() {
            let ciphertext = encryptor.update(&cleartext);
            emit(&ciphertext).await?;
        }
    }

    loop {
        let chunk = read_chunk(reader)
            .await
            .map_err(|_| CipherPrepareAttachmentUpgradeError::StreamIo)?;
        let bytes = match chunk {
            None => break,
            Some(bytes) if bytes.is_empty() => continue,
            Some(bytes) => bytes,
        };
        let cleartext = decryptor.update(&bytes);
        if !cleartext.is_empty() {
            let ciphertext = encryptor.update(&cleartext);
            emit(&ciphertext).await?;
        }
    }

    // Verifies the legacy MAC; any prior writes are only trustworthy after this returns Ok.
    let cleartext_tail = decryptor.finalize(legacy_mac).map_err(DecryptError::from)?;
    if !cleartext_tail.is_empty() {
        let ciphertext = encryptor.update(&cleartext_tail);
        emit(&ciphertext).await?;
    }
    let final_ = encryptor.finalize();
    emit(&final_.trailing_ciphertext).await?;

    writer
        .close()
        .await
        .map_err(|_| CipherPrepareAttachmentUpgradeError::StreamIo)?;

    Ok(UpgradeStreamOutput {
        size,
        iv: final_.iv,
        mac: final_.mac,
    })
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl AttachmentsClient {
    /// Streams a legacy attachment through the SDK and upgrades it to the per-attachment-
    /// key format. The host feeds the downloaded body (header included) into `reader` and
    /// receives the re-encrypted body via `writer`. On `Ok`, the caller composes
    /// `encType (0x02) || iv || mac || <body>` and uploads it; bytes written to `writer`
    /// are unauthenticated until this resolves. See [`prepare_attachment_upgrade`] for the
    /// full contract.
    pub async fn prepare_attachment_upgrade(
        &self,
        cipher_id: CipherId,
        attachment_id: String,
        reader: AttachmentByteReader,
        writer: AttachmentByteWriter,
    ) -> Result<AttachmentUpgrade, CipherPrepareAttachmentUpgradeError> {
        prepare_attachment_upgrade(
            cipher_id,
            &attachment_id,
            &reader,
            &writer,
            &self.api_configurations.api_client,
            self.repository.require()?.as_ref(),
            &self.key_store,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::EncString;
    use bitwarden_state::repository::Repository;
    use bitwarden_test::MemoryRepository;

    use super::*;
    use crate::{Attachment, CipherRepromptType, CipherType};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_ATTACHMENT_ID: &str = "legacyatt0000000000000000000000";
    const TEST_FILE_NAME: &str = "2.mV50WiLq6duhwGbhM1TO0A==|dTufWNH8YTPP0EMlNLIpFA==|QHp+7OM8xHtEmCfc9QPXJ0Ro2BeakzvLgxJZ7NdLuDc=";
    const TEST_KEY: &str = "2.6TPEiYULFg/4+3CpDRwCqw==|6swweBHCJcd5CHdwBBWuRN33XRV22VoroDFDUmiM4OzjPEAhgZK57IZS1KkBlCcFvT+t+YbsmDcdv+Lqr+iJ3MmzfJ40MCB5TfYy+22HVRA=|rkgFDh2IWTfPC1Y66h68Diiab/deyi1p/X0Fwkva0NQ=";

    fn cipher_with_attachment(attachment_key: Option<EncString>) -> Cipher {
        Cipher {
            id: TEST_CIPHER_ID.parse().ok(),
            name: "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=".parse().unwrap(),
            r#type: CipherType::Login,
            attachments: Some(vec![Attachment {
                id: Some(TEST_ATTACHMENT_ID.to_string()),
                url: Some("http://localhost:4000/attachments/legacy".to_string()),
                file_name: Some(TEST_FILE_NAME.parse().unwrap()),
                key: attachment_key,
                size: Some("65".to_string()),
                size_name: Some("65 Bytes".to_string()),
            }]),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            notes: None,
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
            organization_use_totp: true,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            fields: None,
            password_history: None,
            creation_date: "2024-05-31T11:20:58.4566667Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-05-31T11:20:58.4566667Z".parse().unwrap(),
            archived_date: None,
            data: None,
        }
    }

    #[tokio::test]
    async fn lookup_returns_not_found_when_repository_empty() {
        let key_store = KeyStore::<KeySlotIds>::default();
        let repository = MemoryRepository::<Cipher>::default();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let err = lookup_upgrade_target(cipher_id, TEST_ATTACHMENT_ID, &repository, &key_store)
            .await
            .unwrap_err();

        assert!(matches!(err, CipherPrepareAttachmentUpgradeError::NotFound));
    }

    #[tokio::test]
    async fn lookup_returns_not_found_when_attachment_missing() {
        let key_store = KeyStore::<KeySlotIds>::default();
        let repository = MemoryRepository::<Cipher>::default();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let mut cipher = cipher_with_attachment(None);
        cipher.attachments = None;
        repository.set(cipher_id, cipher).await.unwrap();

        let err = lookup_upgrade_target(cipher_id, TEST_ATTACHMENT_ID, &repository, &key_store)
            .await
            .unwrap_err();

        assert!(matches!(err, CipherPrepareAttachmentUpgradeError::NotFound));
    }

    #[tokio::test]
    async fn lookup_returns_already_upgraded_when_attachment_has_key() {
        let key_store = KeyStore::<KeySlotIds>::default();
        let repository = MemoryRepository::<Cipher>::default();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        repository
            .set(
                cipher_id,
                cipher_with_attachment(Some(TEST_KEY.parse().unwrap())),
            )
            .await
            .unwrap();

        let err = lookup_upgrade_target(cipher_id, TEST_ATTACHMENT_ID, &repository, &key_store)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            CipherPrepareAttachmentUpgradeError::AlreadyUpgraded
        ));
    }
}
