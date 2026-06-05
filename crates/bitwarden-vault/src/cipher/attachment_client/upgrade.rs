use std::io;

use bitwarden_api_base::AuthRequired;
use bitwarden_core::{ApiError, MissingFieldError, key_management::SymmetricKeySlotId};
use bitwarden_crypto::{
    CryptoError, Decryptable, EncString, IdentifyKey, PrimitiveEncryptable,
    StreamingAttachmentDecryptor, StreamingAttachmentEncryptor, SymmetricCryptoKey,
};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{RepositoryError, RepositoryOption};
use futures::TryStreamExt;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio_util::io::StreamReader;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::{
    create::{
        AttachmentFileUploadType, CipherCreateAttachmentError, CreateAttachmentRequest,
        CreatedAttachment,
    },
    delete::CipherDeleteAttachmentError,
    download_url::CipherGetAttachmentDownloadUrlError,
};
use crate::{
    AttachmentsClient, Cipher, CipherError, CipherId, CipherView, DecryptError, EncryptError,
    VaultParseError,
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CipherUpgradeAttachmentError {
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
    #[error(transparent)]
    DeleteAttachment(#[from] CipherDeleteAttachmentError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("Cipher or attachment not found")]
    NotFound,
    #[error("Attachment already has a key (no upgrade needed)")]
    AlreadyUpgraded,
    #[error("Failed to download the legacy attachment")]
    Download,
    #[error("Failed to upload the re-encrypted attachment")]
    Upload,
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for CipherUpgradeAttachmentError {
    fn from(value: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(value.into())
    }
}

/// Data needed to re-encrypt an attachment
struct ReencryptionMaterial {
    /// New attachment key, kept raw so it survives the create-slot await.
    new_attachment_key: SymmetricCryptoKey,
    /// New key wrapped with the cipher key for the attachment record.
    wrapped_new_attachment_key: EncString,
    /// File name encrypted with the cipher key.
    encrypted_file_name: EncString,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl AttachmentsClient {
    /// Upgrades a legacy v1 attachment to `CipherKey(AttachmentKey(Contents))`.
    ///
    /// Downloads and re-encrypts the attachment, creates a new slot, uploads the
    /// new bytes, then deletes the old attachment. If the upload fails, it tries
    /// to delete the new slot before returning the error. Returns the decrypted
    /// cipher view.
    pub async fn upgrade_attachment(
        &self,
        cipher_id: CipherId,
        attachment_id: String,
    ) -> Result<CipherView, CipherUpgradeAttachmentError> {
        let repository = self.repository.require()?;
        let cipher = repository
            .get(cipher_id)
            .await?
            .ok_or(CipherUpgradeAttachmentError::NotFound)?;

        let attachment = cipher
            .attachments
            .as_ref()
            .and_then(|atts| {
                atts.iter()
                    .find(|a| a.id.as_deref() == Some(&attachment_id))
            })
            .ok_or(CipherUpgradeAttachmentError::NotFound)?;

        if attachment.key.is_some() {
            return Err(CipherUpgradeAttachmentError::AlreadyUpgraded);
        }

        // Used only to pre-size the encryptor buffer. The legacy encrypted size is
        // a safe upper bound here.
        let plaintext_size_hint: u64 = attachment
            .size
            .as_ref()
            .and_then(|s| s.parse().ok())
            .ok_or(MissingFieldError("attachment.size"))?;

        let file_name_plain = {
            let mut ctx = self.key_store.context();
            let cipher_key =
                Cipher::decrypt_cipher_key(&mut ctx, cipher.key_identifier(), &cipher.key)?;
            attachment
                .decrypt(&mut ctx, cipher_key)
                .map_err(DecryptError::from)?
                .file_name
                .ok_or(MissingFieldError("file_name"))?
        };

        let download_url = self
            .get_attachment_download_url(cipher_id, attachment_id.clone(), None)
            .await?;

        let material = self.prepare_reencryption_material(&cipher, &file_name_plain)?;

        // Re-encrypt first so we can size the new slot from the actual output.
        // This also avoids creating a new slot if download or decrypt fails.
        let reencrypted = self
            .download_and_reencrypt(
                cipher.key_identifier(),
                material.new_attachment_key,
                plaintext_size_hint,
                &download_url,
            )
            .await?;

        let request = CreateAttachmentRequest {
            key: material.wrapped_new_attachment_key,
            file_name: material.encrypted_file_name,
            file_size: reencrypted.len() as u64,
            last_known_revision_date: cipher.revision_date,
            as_admin: false,
        };
        let created = self.create_attachment(cipher_id, request).await?;

        if let Err(e) = self
            .upload_reencrypted(cipher_id, &created, reencrypted)
            .await
        {
            // Upload failed after we created the new slot, so try to clean it up.
            if let Err(rollback_err) = self
                .delete_attachment(cipher_id, created.attachment_id.clone())
                .await
            {
                tracing::warn!(
                    "failed to roll back orphaned attachment slot {} on cipher {cipher_id}: {rollback_err:?}",
                    created.attachment_id,
                );
            }
            return Err(e);
        }

        let upgraded_cipher = self.delete_attachment(cipher_id, attachment_id).await?;

        Ok(self
            .key_store
            .decrypt(&upgraded_cipher)
            .map_err(DecryptError::from)?)
    }
}

impl AttachmentsClient {
    /// Prepares the metadata needed to re-encrypt the attachment.
    ///
    /// Keeps `KeyStoreContext` scoped here so it does not live across `.await`.
    /// The new key is generated here and added again during upload.
    /// The legacy key is looked up by slot ID in the decryptor.
    fn prepare_reencryption_material(
        &self,
        cipher: &Cipher,
        file_name_plain: &str,
    ) -> Result<ReencryptionMaterial, CipherUpgradeAttachmentError> {
        let mut ctx = self.key_store.context();

        let cipher_key =
            Cipher::decrypt_cipher_key(&mut ctx, cipher.key_identifier(), &cipher.key)?;

        let new_attachment_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let new_slot = ctx.add_local_symmetric_key(new_attachment_key.clone());

        let wrapped_new_attachment_key = ctx.wrap_symmetric_key(cipher_key, new_slot)?;
        let encrypted_file_name = file_name_plain.encrypt(&mut ctx, cipher_key)?;

        Ok(ReencryptionMaterial {
            new_attachment_key,
            wrapped_new_attachment_key,
            encrypted_file_name,
        })
    }

    /// Downloads the legacy ciphertext and re-encrypts it into memory.
    ///
    /// Download and decrypt still stream, but the encrypted output is buffered
    /// because `StreamingAttachmentEncryptor` needs the full payload before it
    /// can write, and wasm `reqwest` only supports buffered request bodies.
    async fn download_and_reencrypt(
        &self,
        legacy_key_slot: SymmetricKeySlotId,
        new_attachment_key: SymmetricCryptoKey,
        plaintext_size_hint: u64,
        download_url: &str,
    ) -> Result<Vec<u8>, CipherUpgradeAttachmentError> {
        let response = self
            .http_client
            .get(download_url)
            .send()
            .await
            .map_err(|_| CipherUpgradeAttachmentError::Download)?;
        if !response.status().is_success() {
            return Err(CipherUpgradeAttachmentError::Download);
        }

        let download_reader = StreamReader::new(response.bytes_stream().map_err(io::Error::other));

        // Scope `KeyStoreContext` to construction so it is dropped before any `.await`.
        let mut decryptor = {
            let ctx = self.key_store.context();
            StreamingAttachmentDecryptor::new(legacy_key_slot, ctx, download_reader)?
        };

        // Scope the encryptor so the borrow of `reencrypted` ends before return.
        let mut reencrypted = Vec::<u8>::with_capacity(plaintext_size_hint as usize + 64);
        {
            let mut encryptor = {
                let mut ctx = self.key_store.context();
                let slot = ctx.add_local_symmetric_key(new_attachment_key);
                // This only pre-sizes the buffer. The legacy encrypted size is a safe
                // over-estimate.
                StreamingAttachmentEncryptor::new(
                    slot,
                    ctx,
                    &mut reencrypted,
                    plaintext_size_hint as usize,
                )?
            };
            tokio::io::copy(&mut decryptor, &mut encryptor).await?;
            encryptor.shutdown().await?;
        }

        Ok(reencrypted)
    }

    /// Uploads the re-encrypted bytes to the newly created attachment slot.
    ///
    /// Transport depends on [`AttachmentFileUploadType`]: `Azure` PUTs to the presigned blob URL
    /// on the unauthenticated client (the SAS token in the URL authorizes it; a Bearer token must
    /// not be attached), while `Direct` POSTs to the authenticated Bitwarden API endpoint
    /// (`POST /ciphers/{id}/attachment/{attachmentId}`) using the configured API client.
    async fn upload_reencrypted(
        &self,
        cipher_id: CipherId,
        created: &CreatedAttachment,
        reencrypted: Vec<u8>,
    ) -> Result<(), CipherUpgradeAttachmentError> {
        match created.file_upload_type {
            AttachmentFileUploadType::Azure => {
                let response = self
                    .http_client
                    .put(&created.upload_url)
                    .header("x-ms-blob-type", "BlockBlob")
                    .body(reencrypted)
                    .send()
                    .await
                    .map_err(|_| CipherUpgradeAttachmentError::Upload)?;
                if !response.status().is_success() {
                    return Err(CipherUpgradeAttachmentError::Upload);
                }
            }
            AttachmentFileUploadType::Direct => {
                let url = format!(
                    "{}/ciphers/{}/attachment/{}",
                    self.api_configurations.api_config.base_path,
                    bitwarden_api_base::urlencode(cipher_id.to_string()),
                    bitwarden_api_base::urlencode(&created.attachment_id),
                );
                let part = reqwest::multipart::Part::bytes(reencrypted).file_name("data");
                let form = reqwest::multipart::Form::new().part("data", part);
                let request = self
                    .api_configurations
                    .api_config
                    .client
                    .post(url)
                    .with_extension(AuthRequired::Bearer)
                    .multipart(form);
                bitwarden_api_base::process_with_empty_response(request)
                    .await
                    .map_err(|_: bitwarden_api_api::apis::Error<()>| {
                        CipherUpgradeAttachmentError::Upload
                    })?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            AttachmentResponseModel, AttachmentUploadDataResponseModel, CipherMiniResponseModel,
            CipherResponseModel, DeleteAttachmentResponseModel,
        },
    };
    use bitwarden_core::{
        client::ApiConfigurations,
        key_management::{KeySlotIds, create_test_crypto_with_user_key},
    };
    use bitwarden_crypto::KeyStore;
    use bitwarden_state::repository::Repository;
    use bitwarden_test::MemoryRepository;

    use super::*;
    use crate::{Attachment, CipherRepromptType, CipherType};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const OLD_ATTACHMENT_ID: &str = "uf7bkexzag04d3cw04jsbqqkbpbwhxs0";
    const NEW_ATTACHMENT_ID: &str = "newatt9999999999999999999999999";
    const TEST_CIPHER_NAME: &str = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";
    // Pre-encrypted file name used in tests that do not decrypt the cipher.
    const TEST_FILE_NAME: &str = "2.mV50WiLq6duhwGbhM1TO0A==|dTufWNH8YTPP0EMlNLIpFA==|QHp+7OM8xHtEmCfc9QPXJ0Ro2BeakzvLgxJZ7NdLuDc=";
    const TEST_KEY: &str = "2.6TPEiYULFg/4+3CpDRwCqw==|6swweBHCJcd5CHdwBBWuRN33XRV22VoroDFDUmiM4OzjPEAhgZK57IZS1KkBlCcFvT+t+YbsmDcdv+Lqr+iJ3MmzfJ40MCB5TfYy+22HVRA=|rkgFDh2IWTfPC1Y66h68Diiab/deyi1p/X0Fwkva0NQ=";

    fn client(
        api_client: ApiClient,
        repository: MemoryRepository<Cipher>,
        key_store: KeyStore<KeySlotIds>,
        api_base_url: &str,
    ) -> AttachmentsClient {
        // `Direct` uploads go through the authenticated API client at `api_config.base_path`
        let mut api_configurations = ApiConfigurations::from_api_client(api_client);
        api_configurations.api_config.base_path = api_base_url.to_string();
        AttachmentsClient {
            key_store,
            api_configurations: Arc::new(api_configurations),
            repository: Some(Arc::new(repository)),
            http_client: reqwest::Client::new(),
        }
    }

    fn cipher_with(name: EncString, attachments: Option<Vec<Attachment>>) -> Cipher {
        Cipher {
            id: TEST_CIPHER_ID.parse().ok(),
            name,
            r#type: CipherType::Login,
            attachments,
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

    fn attachment_model(id: &str) -> AttachmentResponseModel {
        AttachmentResponseModel {
            id: Some(id.to_string()),
            ..Default::default()
        }
    }

    fn server_cipher_response() -> CipherResponseModel {
        CipherResponseModel {
            id: Some(TEST_CIPHER_ID.try_into().unwrap()),
            name: Some(TEST_CIPHER_NAME.to_string()),
            r#type: Some(bitwarden_api_api::models::CipherType::Login),
            creation_date: Some("2024-05-31T11:20:58.4566667Z".to_string()),
            revision_date: Some("2024-05-31T11:20:58.4566667Z".to_string()),
            attachments: Some(vec![
                attachment_model(OLD_ATTACHMENT_ID),
                attachment_model(NEW_ATTACHMENT_ID),
            ]),
            ..Default::default()
        }
    }

    // `upgrade_attachment` returns the decrypted delete result, so the delete response's name
    // must decrypt under the test user key. Callers pass a name produced by `encrypted_name`.
    fn server_cipher_mini_response(name: String) -> CipherMiniResponseModel {
        CipherMiniResponseModel {
            id: Some(TEST_CIPHER_ID.try_into().unwrap()),
            name: Some(name),
            r#type: Some(bitwarden_api_api::models::CipherType::Login),
            creation_date: Some("2024-05-31T11:20:58.4566667Z".to_string()),
            revision_date: Some("2024-05-31T11:20:58.4566667Z".to_string()),
            attachments: Some(vec![attachment_model(NEW_ATTACHMENT_ID)]),
            ..Default::default()
        }
    }

    fn encrypted_name(key_store: &KeyStore<KeySlotIds>) -> String {
        "Upgraded cipher"
            .encrypt(&mut key_store.context(), SymmetricKeySlotId::User)
            .expect("encrypt name")
            .to_string()
    }

    /// Builds legacy attachment bytes: `[0x02][IV][HMAC][ciphertext]`,
    /// encrypted under the user key.
    async fn make_legacy_wire(key_store: &KeyStore<KeySlotIds>, plaintext: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        {
            let ctx = key_store.context();
            let mut enc = StreamingAttachmentEncryptor::new(
                SymmetricKeySlotId::User,
                ctx,
                &mut wire,
                plaintext.len(),
            )
            .expect("encryptor construction");
            enc.write_all(plaintext).await.expect("write_all");
            enc.shutdown().await.expect("shutdown");
        }
        wire
    }

    /// Builds a legacy cipher with one keyless attachment so the cipher still decrypts.
    fn legacy_cipher(key_store: &KeyStore<KeySlotIds>, encrypted_size: usize) -> Cipher {
        let mut ctx = key_store.context();
        let name = "Upgrade test cipher"
            .encrypt(&mut ctx, SymmetricKeySlotId::User)
            .expect("encrypt name");
        let file_name = "hello.txt"
            .encrypt(&mut ctx, SymmetricKeySlotId::User)
            .expect("encrypt file name");
        drop(ctx);

        cipher_with(
            name,
            Some(vec![Attachment {
                id: Some(OLD_ATTACHMENT_ID.to_string()),
                url: None,
                file_name: Some(file_name),
                key: None,
                size: Some(encrypted_size.to_string()),
                size_name: Some(format!("{encrypted_size} Bytes")),
            }]),
        )
    }

    #[tokio::test]
    async fn returns_not_found_when_cipher_missing() {
        let api_client = ApiClient::new_mocked(|_mock| {});
        let key_store =
            create_test_crypto_with_user_key(SymmetricCryptoKey::make_aes256_cbc_hmac_key());
        let client = client(
            api_client,
            MemoryRepository::<Cipher>::default(),
            key_store,
            "",
        );
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let err = client
            .upgrade_attachment(cipher_id, OLD_ATTACHMENT_ID.to_string())
            .await
            .unwrap_err();

        assert!(matches!(err, CipherUpgradeAttachmentError::NotFound));
    }

    #[tokio::test]
    async fn returns_not_found_when_attachment_missing() {
        let api_client = ApiClient::new_mocked(|_mock| {});
        let key_store =
            create_test_crypto_with_user_key(SymmetricCryptoKey::make_aes256_cbc_hmac_key());

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let repository = MemoryRepository::<Cipher>::default();
        repository
            .set(
                cipher_id,
                cipher_with(TEST_CIPHER_NAME.parse().unwrap(), None),
            )
            .await
            .unwrap();

        let client = client(api_client, repository, key_store, "");

        let err = client
            .upgrade_attachment(cipher_id, OLD_ATTACHMENT_ID.to_string())
            .await
            .unwrap_err();

        assert!(matches!(err, CipherUpgradeAttachmentError::NotFound));
    }

    #[tokio::test]
    async fn returns_already_upgraded_when_attachment_has_key() {
        let api_client = ApiClient::new_mocked(|_mock| {});
        let key_store =
            create_test_crypto_with_user_key(SymmetricCryptoKey::make_aes256_cbc_hmac_key());

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let repository = MemoryRepository::<Cipher>::default();
        repository
            .set(
                cipher_id,
                cipher_with(
                    TEST_CIPHER_NAME.parse().unwrap(),
                    Some(vec![Attachment {
                        id: Some(OLD_ATTACHMENT_ID.to_string()),
                        url: None,
                        file_name: Some(TEST_FILE_NAME.parse().unwrap()),
                        // Already-modern attachment: it carries its own wrapped key.
                        key: Some(TEST_KEY.parse().unwrap()),
                        size: Some("65".to_string()),
                        size_name: Some("65 Bytes".to_string()),
                    }]),
                ),
            )
            .await
            .unwrap();

        let client = client(api_client, repository, key_store, "");

        let err = client
            .upgrade_attachment(cipher_id, OLD_ATTACHMENT_ID.to_string())
            .await
            .unwrap_err();

        assert!(matches!(err, CipherUpgradeAttachmentError::AlreadyUpgraded));
    }

    #[tokio::test]
    async fn upgrades_legacy_attachment_via_direct_upload() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

        let key_store =
            create_test_crypto_with_user_key(SymmetricCryptoKey::make_aes256_cbc_hmac_key());
        let wire = make_legacy_wire(&key_store, b"Hello, attachment upgrade world!").await;
        let encrypted_size = wire.len();
        let mini_name = encrypted_name(&key_store);

        // Direct uploads go to the authenticated API endpoint, not the returned `url`.
        let upload_path = format!("/ciphers/{TEST_CIPHER_ID}/attachment/{NEW_ATTACHMENT_ID}");

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/download/old"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(wire.clone()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(upload_path.clone()))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let download_url = format!("{}/download/old", server.uri());

        let api_client = ApiClient::new_mocked(move |mock| {
            let download_url = download_url.clone();
            mock.ciphers_api
                .expect_get_attachment_data()
                .returning(move |_id, _att| {
                    Ok(AttachmentResponseModel {
                        id: Some(OLD_ATTACHMENT_ID.to_string()),
                        url: Some(download_url.clone()),
                        ..Default::default()
                    })
                });
            mock.ciphers_api
                .expect_post_attachment()
                .returning(move |_id, _req| {
                    Ok(AttachmentUploadDataResponseModel {
                        attachment_id: Some(NEW_ATTACHMENT_ID.to_string()),
                        // `url` is ignored for Direct uploads.
                        url: Some("https://unused.example/direct".to_string()),
                        file_upload_type: Some(bitwarden_api_api::models::FileUploadType::Direct),
                        cipher_response: Some(Box::new(server_cipher_response())),
                        cipher_mini_response: None,
                        ..Default::default()
                    })
                });
            // On success the *legacy* attachment is deleted; the new slot is kept.
            mock.ciphers_api
                .expect_delete_attachment()
                .withf(|_id, att_id| att_id == OLD_ATTACHMENT_ID)
                .times(1)
                .returning({
                    let mini_name = mini_name.clone();
                    move |_id, _att| {
                        Ok(DeleteAttachmentResponseModel {
                            object: None,
                            cipher: Some(Box::new(server_cipher_mini_response(mini_name.clone()))),
                        })
                    }
                });
        });

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let repository = MemoryRepository::<Cipher>::default();
        repository
            .set(cipher_id, legacy_cipher(&key_store, encrypted_size))
            .await
            .unwrap();

        let client = client(api_client, repository, key_store, &server.uri());

        let cipher = client
            .upgrade_attachment(cipher_id, OLD_ATTACHMENT_ID.to_string())
            .await
            .unwrap();
        assert_eq!(cipher.id, Some(cipher_id));

        // The returned cipher must reflect the post-delete state, not the slot-creation snapshot:
        // the legacy attachment is gone and the new one remains.
        let returned_ids: Vec<String> = cipher
            .attachments
            .unwrap_or_default()
            .into_iter()
            .filter_map(|a| a.id)
            .collect();
        assert!(
            !returned_ids.contains(&OLD_ATTACHMENT_ID.to_string()),
            "returned cipher must not list the deleted legacy attachment, got {returned_ids:?}"
        );
        assert!(
            returned_ids.contains(&NEW_ATTACHMENT_ID.to_string()),
            "returned cipher should list the upgraded attachment, got {returned_ids:?}"
        );

        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.url.path() == "/download/old")
                .count(),
            1,
            "legacy ciphertext should be downloaded exactly once"
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.url.path() == upload_path.as_str())
                .count(),
            1,
            "Direct upload should hit the authenticated attachment endpoint exactly once"
        );
    }

    #[tokio::test]
    async fn upgrades_legacy_attachment_via_azure_upload() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method, path},
        };

        let key_store =
            create_test_crypto_with_user_key(SymmetricCryptoKey::make_aes256_cbc_hmac_key());
        let wire = make_legacy_wire(&key_store, b"azure upload path plaintext").await;
        let encrypted_size = wire.len();
        let mini_name = encrypted_name(&key_store);

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/download/old"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(wire.clone()))
            .mount(&server)
            .await;
        // Azure uploads PUT directly to the presigned blob URL with the BlockBlob header.
        Mock::given(method("PUT"))
            .and(path("/upload/blob"))
            .and(header("x-ms-blob-type", "BlockBlob"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let download_url = format!("{}/download/old", server.uri());
        let upload_url = format!("{}/upload/blob", server.uri());

        let api_client = ApiClient::new_mocked(move |mock| {
            let download_url = download_url.clone();
            mock.ciphers_api
                .expect_get_attachment_data()
                .returning(move |_id, _att| {
                    Ok(AttachmentResponseModel {
                        id: Some(OLD_ATTACHMENT_ID.to_string()),
                        url: Some(download_url.clone()),
                        ..Default::default()
                    })
                });
            let upload_url = upload_url.clone();
            mock.ciphers_api
                .expect_post_attachment()
                .returning(move |_id, _req| {
                    Ok(AttachmentUploadDataResponseModel {
                        attachment_id: Some(NEW_ATTACHMENT_ID.to_string()),
                        url: Some(upload_url.clone()),
                        file_upload_type: Some(bitwarden_api_api::models::FileUploadType::Azure),
                        cipher_response: Some(Box::new(server_cipher_response())),
                        cipher_mini_response: None,
                        ..Default::default()
                    })
                });
            mock.ciphers_api
                .expect_delete_attachment()
                .withf(|_id, att_id| att_id == OLD_ATTACHMENT_ID)
                .times(1)
                .returning({
                    let mini_name = mini_name.clone();
                    move |_id, _att| {
                        Ok(DeleteAttachmentResponseModel {
                            object: None,
                            cipher: Some(Box::new(server_cipher_mini_response(mini_name.clone()))),
                        })
                    }
                });
        });

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let repository = MemoryRepository::<Cipher>::default();
        repository
            .set(cipher_id, legacy_cipher(&key_store, encrypted_size))
            .await
            .unwrap();

        // Azure uses the presigned URL on the unauthenticated client, so `base_path` is unused.
        let client = client(api_client, repository, key_store, "");

        let cipher = client
            .upgrade_attachment(cipher_id, OLD_ATTACHMENT_ID.to_string())
            .await
            .unwrap();
        assert_eq!(cipher.id, Some(cipher_id));

        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.url.path() == "/upload/blob")
                .count(),
            1,
            "Azure upload should PUT to the presigned blob URL exactly once"
        );
    }

    #[tokio::test]
    async fn rolls_back_new_slot_when_upload_fails() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

        let key_store =
            create_test_crypto_with_user_key(SymmetricCryptoKey::make_aes256_cbc_hmac_key());
        let wire = make_legacy_wire(&key_store, b"rollback path plaintext").await;
        let encrypted_size = wire.len();
        let mini_name = encrypted_name(&key_store);

        let upload_path = format!("/ciphers/{TEST_CIPHER_ID}/attachment/{NEW_ATTACHMENT_ID}");

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/download/old"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(wire.clone()))
            .mount(&server)
            .await;
        // Upload fails — the orphaned new slot must be rolled back.
        Mock::given(method("POST"))
            .and(path(upload_path))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let download_url = format!("{}/download/old", server.uri());

        let api_client = ApiClient::new_mocked(move |mock| {
            let download_url = download_url.clone();
            mock.ciphers_api
                .expect_get_attachment_data()
                .returning(move |_id, _att| {
                    Ok(AttachmentResponseModel {
                        id: Some(OLD_ATTACHMENT_ID.to_string()),
                        url: Some(download_url.clone()),
                        ..Default::default()
                    })
                });
            mock.ciphers_api
                .expect_post_attachment()
                .returning(move |_id, _req| {
                    Ok(AttachmentUploadDataResponseModel {
                        attachment_id: Some(NEW_ATTACHMENT_ID.to_string()),
                        url: Some("https://unused.example/direct".to_string()),
                        file_upload_type: Some(bitwarden_api_api::models::FileUploadType::Direct),
                        cipher_response: Some(Box::new(server_cipher_response())),
                        cipher_mini_response: None,
                        ..Default::default()
                    })
                });
            // Rollback must delete the *new* slot, never the legacy one.
            mock.ciphers_api
                .expect_delete_attachment()
                .withf(|_id, att_id| att_id == NEW_ATTACHMENT_ID)
                .times(1)
                .returning({
                    let mini_name = mini_name.clone();
                    move |_id, _att| {
                        Ok(DeleteAttachmentResponseModel {
                            object: None,
                            cipher: Some(Box::new(server_cipher_mini_response(mini_name.clone()))),
                        })
                    }
                });
        });

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let repository = MemoryRepository::<Cipher>::default();
        repository
            .set(cipher_id, legacy_cipher(&key_store, encrypted_size))
            .await
            .unwrap();

        let client = client(api_client, repository, key_store, &server.uri());

        let err = client
            .upgrade_attachment(cipher_id, OLD_ATTACHMENT_ID.to_string())
            .await
            .unwrap_err();

        assert!(matches!(err, CipherUpgradeAttachmentError::Upload));
    }
}
