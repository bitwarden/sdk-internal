use bitwarden_core::{ApiError, MissingFieldError, key_management::KeySlotIds};
use bitwarden_crypto::{EncString, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError, RepositoryOption};
use chrono::SecondsFormat;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

use super::{
    create::{
        CipherCreateAttachmentError, CreateAttachmentRequest, FileUploadType, create_attachment,
    },
    download_url::{CipherGetAttachmentDownloadUrlError, get_attachment_download_url},
};
use crate::{
    AttachmentFile, AttachmentFileView, AttachmentsClient, Cipher, CipherError, CipherId,
    CipherView, DecryptError, EncryptError, VaultParseError,
};

/// Errors returned from preparing an attachment upgrade.
#[allow(missing_docs)]
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
    #[error("Failed to download attachment")]
    Download,
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for CipherPrepareAttachmentUpgradeError {
    fn from(value: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(value.into())
    }
}

/// Data the caller needs to finish a legacy-attachment upgrade. The SDK has fetched the
/// legacy bytes, decrypted them, re-encrypted them with a freshly-generated attachment
/// key, opened a new attachment slot on the server, and persisted the updated cipher to
/// the local repository. The caller pushes [`Self::encrypted_contents`] to
/// [`Self::upload_url`] and then deletes the legacy attachment via
/// [`AttachmentsClient::delete_attachment`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct AttachmentUpgrade {
    /// Server-assigned ID of the new attachment.
    pub attachment_id: String,
    /// URL to push the encrypted bytes to (presigned blob URL or local server endpoint).
    pub upload_url: String,
    /// Where to push the bytes — local Bitwarden server (`Direct`) or Azure Blob storage.
    pub file_upload_type: FileUploadType,
    /// Encrypted file name in `EncString` format.
    pub encrypted_file_name: String,
    /// Encrypted file bytes ready to push to `upload_url`.
    pub encrypted_contents: Vec<u8>,
}

/// Prepare a legacy attachment for upgrading to the cipher-key-encryption format.
///
/// Downloads the legacy ciphertext, re-encrypts it with a freshly-generated attachment key,
/// opens a new attachment slot on the server, and updates the local repository. Returns
/// the upload URL and encrypted bytes; the caller pushes the bytes and then deletes the
/// legacy attachment via [`AttachmentsClient::delete_attachment`].
pub async fn prepare_attachment_upgrade<R: Repository<Cipher> + ?Sized>(
    cipher_id: CipherId,
    attachment_id: &str,
    api_client: &bitwarden_api_api::apis::ApiClient,
    http_client: &reqwest::Client,
    repository: &R,
    key_store: &KeyStore<KeySlotIds>,
) -> Result<AttachmentUpgrade, CipherPrepareAttachmentUpgradeError> {
    let cipher = repository
        .get(cipher_id)
        .await?
        .ok_or(CipherPrepareAttachmentUpgradeError::NotFound)?;

    // Precondition checks on the encrypted cipher avoid a wasted decrypt on the
    // already-upgraded / missing-attachment paths.
    let attachment = cipher
        .attachments
        .as_ref()
        .and_then(|atts| atts.iter().find(|a| a.id.as_deref() == Some(attachment_id)))
        .ok_or(CipherPrepareAttachmentUpgradeError::NotFound)?;

    if attachment.key.is_some() {
        return Err(CipherPrepareAttachmentUpgradeError::AlreadyUpgraded);
    }

    let cipher_view: CipherView = key_store.decrypt(&cipher).map_err(DecryptError::from)?;
    let attachment_view = cipher_view
        .attachments
        .as_ref()
        .and_then(|atts| atts.iter().find(|a| a.id.as_deref() == Some(attachment_id)))
        .cloned()
        .ok_or(CipherPrepareAttachmentUpgradeError::NotFound)?;

    let download_url =
        get_attachment_download_url(cipher_id, attachment_id, api_client, repository).await?;

    // Presigned URLs already carry their auth; bypass the api_client middleware.
    let response = http_client
        .get(&download_url)
        .send()
        .await
        .map_err(|_| CipherPrepareAttachmentUpgradeError::Download)?;

    if !response.status().is_success() {
        return Err(CipherPrepareAttachmentUpgradeError::Download);
    }

    let encrypted_buffer = response
        .bytes()
        .await
        .map_err(|_| CipherPrepareAttachmentUpgradeError::Download)?;

    let contents = EncString::from_buffer(&encrypted_buffer).map_err(DecryptError::from)?;
    let cleartext: Zeroizing<Vec<u8>> = Zeroizing::new(
        key_store
            .decrypt(&AttachmentFile {
                cipher: cipher.clone(),
                attachment: attachment_view.clone(),
                contents,
            })
            .map_err(DecryptError::from)?,
    );

    let encrypt_result = key_store
        .encrypt(AttachmentFileView {
            cipher: cipher.clone(),
            attachment: attachment_view,
            contents: &cleartext,
        })
        .map_err(EncryptError::from)?;

    // Pull request fields out of the encrypt result up front so a missing value fails
    // before we open a server-side slot. After this point everything is infallible
    // until create_attachment, which has its own rollback for post-POST failures.
    let key = encrypt_result
        .attachment
        .key
        .as_ref()
        .ok_or(MissingFieldError("key"))?
        .to_string();
    let encrypted_file_name = encrypt_result
        .attachment
        .file_name
        .as_ref()
        .ok_or(MissingFieldError("file_name"))?
        .to_string();

    let last_known_revision_date = cipher
        .revision_date
        .to_rfc3339_opts(SecondsFormat::Millis, true);

    let request = CreateAttachmentRequest {
        key,
        file_name: encrypted_file_name.clone(),
        file_size: encrypt_result.contents.len() as i64,
        last_known_revision_date,
        as_admin: false,
    };

    let created = create_attachment(cipher_id, request, api_client, repository).await?;

    Ok(AttachmentUpgrade {
        attachment_id: created.attachment_id,
        upload_url: created.upload_url,
        file_upload_type: created.file_upload_type,
        encrypted_file_name,
        encrypted_contents: encrypt_result.contents,
    })
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl AttachmentsClient {
    /// Prepare a legacy attachment for upgrade to the cipher-key-encryption format.
    ///
    /// Returns the data needed to push the re-encrypted bytes to the upload URL. The caller
    /// is responsible for the byte push (see [`AttachmentUpgrade`]) and for deleting the
    /// legacy attachment via [`Self::delete_attachment`] once the push succeeds.
    pub async fn prepare_attachment_upgrade(
        &self,
        cipher_id: CipherId,
        attachment_id: String,
    ) -> Result<AttachmentUpgrade, CipherPrepareAttachmentUpgradeError> {
        prepare_attachment_upgrade(
            cipher_id,
            &attachment_id,
            &self.api_configurations.api_client,
            &self.http_client,
            self.repository.require()?.as_ref(),
            &self.key_store,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
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
    async fn returns_not_found_when_repository_empty() {
        let key_store = KeyStore::<KeySlotIds>::default();
        let api_client = bitwarden_api_api::apis::ApiClient::new_mocked(|_| {});
        let http_client = reqwest::Client::new();
        let repository = MemoryRepository::<Cipher>::default();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let err = prepare_attachment_upgrade(
            cipher_id,
            TEST_ATTACHMENT_ID,
            &api_client,
            &http_client,
            &repository,
            &key_store,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, CipherPrepareAttachmentUpgradeError::NotFound));
    }

    #[tokio::test]
    async fn returns_not_found_when_attachment_missing() {
        let key_store = KeyStore::<KeySlotIds>::default();
        let api_client = bitwarden_api_api::apis::ApiClient::new_mocked(|_| {});
        let http_client = reqwest::Client::new();
        let repository = MemoryRepository::<Cipher>::default();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let mut cipher = cipher_with_attachment(None);
        cipher.attachments = None;
        repository.set(cipher_id, cipher).await.unwrap();

        let err = prepare_attachment_upgrade(
            cipher_id,
            TEST_ATTACHMENT_ID,
            &api_client,
            &http_client,
            &repository,
            &key_store,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, CipherPrepareAttachmentUpgradeError::NotFound));
    }

    #[tokio::test]
    async fn returns_already_upgraded_when_attachment_already_has_key() {
        let key_store = KeyStore::<KeySlotIds>::default();
        let api_client = bitwarden_api_api::apis::ApiClient::new_mocked(|_| {});
        let http_client = reqwest::Client::new();
        let repository = MemoryRepository::<Cipher>::default();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        repository
            .set(
                cipher_id,
                cipher_with_attachment(Some(TEST_KEY.parse().unwrap())),
            )
            .await
            .unwrap();

        let err = prepare_attachment_upgrade(
            cipher_id,
            TEST_ATTACHMENT_ID,
            &api_client,
            &http_client,
            &repository,
            &key_store,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            CipherPrepareAttachmentUpgradeError::AlreadyUpgraded
        ));
    }
}
