use bitwarden_api_base::AuthRequired;
use bitwarden_core::{ApiError, MissingFieldError, require};
use bitwarden_crypto::CryptoError;
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::RepositoryError;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    EmptyEmailListError, Send, SendAddRequest, SendId, SendParseError, SendView,
    send_client::SendClient,
};

/// Where the client should upload the encrypted file bytes after [`SendClient::create_file_send`].
#[derive(Clone, Copy, Serialize_repr, Deserialize_repr, Debug, PartialEq)]
#[repr(u8)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum FileUploadType {
    /// Upload directly to the Bitwarden server via `POST /sends/{id}/file/{file_id}`.
    Direct = 0,
    /// Upload to an Azure Blob Storage pre-signed URL.
    Azure = 1,
}

impl TryFrom<bitwarden_api_api::models::FileUploadType> for FileUploadType {
    type Error = MissingFieldError;

    fn try_from(t: bitwarden_api_api::models::FileUploadType) -> Result<Self, Self::Error> {
        Ok(match t {
            bitwarden_api_api::models::FileUploadType::Direct => FileUploadType::Direct,
            bitwarden_api_api::models::FileUploadType::Azure => FileUploadType::Azure,
            bitwarden_api_api::models::FileUploadType::__Unknown(_) => {
                return Err(MissingFieldError("file_upload_type"));
            }
        })
    }
}

/// View returned after creating a file send.
///
/// Contains the created send and information needed to upload the file data.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi))]
pub struct CreateFileSendResponse {
    /// The created send.
    pub send: SendView,
    /// The upload URL for the file data.
    pub url: String,
    /// Which upload backend the client should target with the encrypted bytes.
    pub file_upload_type: FileUploadType,
    /// The file ID assigned by the server.
    pub file_id: String,
    /// The encrypted file name string (e.g. `"2.ABCD..."`).
    pub encrypted_file_name: String,
}

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CreateFileSendError {
    /// An API or network error occurred.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A cryptographic error occurred.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// An email list validation error occurred.
    #[error(transparent)]
    EmptyEmailList(#[from] EmptyEmailListError),
    /// A required field was missing from the API response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// A repository error occurred.
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    /// A send parse error occurred.
    #[error(transparent)]
    SendParse(#[from] SendParseError),
}

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum UploadSendFileError {
    /// An API or network error occurred.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A reqwest error occurred when building the multipart form.
    #[error(transparent)]
    Reqwest(reqwest::Error),
}

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum RenewFileUploadUrlError {
    /// An API or network error occurred.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A required field was missing from the API response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl SendClient {
    /// Create a new file [Send] and save it to the server.
    ///
    /// Returns the created send along with metadata needed to upload the file data.
    /// After calling this, use [`SendClient::upload_send_file`] to upload the encrypted file.
    pub async fn create_file_send(
        &self,
        request: SendAddRequest,
    ) -> Result<CreateFileSendResponse, CreateFileSendError> {
        request.auth.validate()?;

        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations();
        let repository = self.get_repository()?;

        let send_request = key_store.encrypt(request)?;

        let resp = config
            .api_client
            .sends_api()
            .post_file(Some(send_request))
            .await
            .map_err(ApiError::from)?;

        let url = require!(resp.url);
        let file_upload_type: FileUploadType = require!(resp.file_upload_type).try_into()?;
        let send_response = *require!(resp.send_response);

        let send: Send = send_response.try_into()?;

        let file_id = send
            .file
            .as_ref()
            .and_then(|f| f.id.clone())
            .ok_or(MissingFieldError("file.id"))?;

        let encrypted_file_name = send
            .file
            .as_ref()
            .map(|f| f.file_name.to_string())
            .ok_or(MissingFieldError("file.file_name"))?;

        let send_view = key_store.decrypt(&send)?;

        let send_id = require!(send.id);
        repository.set(send_id, send.clone()).await?;

        Ok(CreateFileSendResponse {
            send: send_view,
            url,
            file_upload_type,
            file_id,
            encrypted_file_name,
        })
    }

    /// Upload the encrypted file data for a file [Send].
    ///
    /// `data` must be the encrypted file content (encrypted with the send key).
    /// `encrypted_file_name` is the encrypted file name string from [`CreateFileSendResponse`].
    pub async fn upload_send_file(
        &self,
        send_id: SendId,
        file_id: String,
        encrypted_file_name: String,
        data: Vec<u8>,
    ) -> Result<(), UploadSendFileError> {
        let config = self.client.internal.get_api_configurations();

        let url = format!(
            "{}/sends/{}/file/{}",
            config.api_config.base_path,
            bitwarden_api_base::urlencode(send_id.to_string()),
            bitwarden_api_base::urlencode(&file_id),
        );

        let part = reqwest::multipart::Part::bytes(data)
            .file_name(encrypted_file_name)
            .mime_str("application/octet-stream")
            .map_err(UploadSendFileError::Reqwest)?;

        let form = reqwest::multipart::Form::new().part("data", part);

        let req_builder = config
            .api_config
            .client
            .post(url)
            .with_extension(AuthRequired::Bearer)
            .multipart(form);

        bitwarden_api_base::process_with_empty_response(req_builder)
            .await
            .map_err(|e: bitwarden_api_api::apis::Error<()>| ApiError::from(e))?;

        Ok(())
    }

    /// Renew the upload URL for a file [Send].
    ///
    /// Returns a fresh upload URL if the previous one has expired.
    pub async fn renew_file_upload_url(
        &self,
        send_id: SendId,
        file_id: String,
    ) -> Result<String, RenewFileUploadUrlError> {
        let config = self.client.internal.get_api_configurations();

        let resp = config
            .api_client
            .sends_api()
            .renew_file_upload(&send_id.to_string(), &file_id)
            .await
            .map_err(ApiError::from)?;

        Ok(require!(resp.url))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::models::{
        FileUploadType, SendFileModel, SendFileUploadDataResponseModel, SendResponseModel,
    };
    use bitwarden_core::{
        Client, ClientSettings, DeviceType,
        key_management::{KeySlotIds, SymmetricKeySlotId},
    };
    use bitwarden_crypto::{KeyStore, SymmetricKeyAlgorithm};
    use bitwarden_state::repository::Repository;
    use bitwarden_test::{MemoryRepository, start_api_mock};
    use uuid::uuid;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, path_regex},
    };

    use super::*;
    use crate::{
        AuthType, Send, SendAuthType, SendClientExt, SendId, SendTextView, SendType, SendViewType,
    };

    const SEND_ID: &str = "25afb11c-9c95-4db5-8bac-c21cb204a3f1";
    const FILE_ID: &str = "file-id-abc";

    /// Builds a [`Client`] whose API and identity URLs point at the supplied wiremock server,
    /// then registers a [`MemoryRepository`] for [`Send`] and installs a fresh symmetric key
    /// in the user slot so that encrypt/decrypt round-trips succeed.
    fn make_test_client(server: &MockServer) -> (Client, Arc<MemoryRepository<Send>>) {
        let settings = ClientSettings {
            identity_url: server.uri(),
            api_url: server.uri(),
            user_agent: "Bitwarden Test".into(),
            device_type: DeviceType::SDK,
            device_identifier: None,
            bitwarden_client_version: None,
            bitwarden_package_type: None,
        };
        let client = Client::new(Some(settings));

        // Seed the user key slot so SendAddRequest::encrypt_composite can wrap the send key.
        {
            let key_store: &KeyStore<KeySlotIds> = client.internal.get_key_store();
            let mut ctx = key_store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeySlotId::User)
                .unwrap();
        }

        let repository = Arc::new(MemoryRepository::<Send>::default());
        client
            .platform()
            .state()
            .register_client_managed(repository.clone());

        (client, repository)
    }

    fn sample_request() -> SendAddRequest {
        SendAddRequest {
            name: "test-file-send".to_string(),
            notes: None,
            // Even file sends use SendViewType::Text for the *request* body since the file
            // content is uploaded separately; the server flips the type on the response.
            view_type: SendViewType::Text(SendTextView {
                text: None,
                hidden: false,
            }),
            max_access_count: None,
            disabled: false,
            hide_email: false,
            deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
            expiration_date: None,
            auth: SendAuthType::None,
        }
    }

    /// Build a [`SendResponseModel`] that echoes the encrypted `name`/`key` from the request,
    /// adds a server-assigned file ID, and is a valid input for `Send::try_from`.
    fn echo_file_send_response(
        request: bitwarden_api_api::models::SendRequestModel,
    ) -> SendResponseModel {
        let encrypted_name = request.name.clone();
        SendResponseModel {
            id: Some(uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1")),
            name: request.name,
            revision_date: Some("2025-01-01T00:00:00Z".to_string()),
            object: Some("send".to_string()),
            access_id: None,
            r#type: Some(bitwarden_api_api::models::SendType::File),
            auth_type: Some(bitwarden_api_api::models::AuthType::None),
            notes: request.notes,
            file: Some(Box::new(SendFileModel {
                id: Some(FILE_ID.to_string()),
                // Re-use the encrypted name as a stand-in for an encrypted file_name; the
                // SDK only requires that this be a parseable EncString.
                file_name: encrypted_name,
                size: Some("123".to_string()),
                size_name: Some("123 B".to_string()),
            })),
            text: None,
            key: Some(request.key),
            max_access_count: request.max_access_count,
            access_count: Some(0),
            password: request.password,
            emails: request.emails,
            disabled: Some(request.disabled),
            expiration_date: request.expiration_date,
            deletion_date: Some(request.deletion_date),
            hide_email: request.hide_email,
        }
    }

    // ===== create_file_send =====

    #[tokio::test]
    async fn test_create_file_send() {
        let upload_url = "https://upload.example.com/abc";
        let mock = Mock::given(method("POST"))
            .and(path("/sends/file/v2"))
            .respond_with(move |req: &wiremock::Request| {
                let body: bitwarden_api_api::models::SendRequestModel =
                    serde_json::from_slice(&req.body).expect("request body should be valid JSON");
                let send_response = echo_file_send_response(body);
                let response = SendFileUploadDataResponseModel {
                    object: Some("send-fileUpload".to_string()),
                    url: Some(upload_url.to_string()),
                    file_upload_type: Some(FileUploadType::Azure),
                    send_response: Some(Box::new(send_response)),
                };
                ResponseTemplate::new(200).set_body_json(&response)
            });

        let (server, _config) = start_api_mock(vec![mock]).await;
        let (client, repository) = make_test_client(&server);

        let result = client
            .sends()
            .create_file_send(sample_request())
            .await
            .unwrap();

        assert_eq!(result.url, upload_url);
        assert_eq!(result.file_upload_type, crate::FileUploadType::Azure);
        assert_eq!(result.file_id, FILE_ID);
        assert!(!result.encrypted_file_name.is_empty());
        assert_eq!(result.send.id, Some(SendId::new(SEND_ID.parse().unwrap())));
        assert_eq!(result.send.name, "test-file-send");
        assert_eq!(result.send.r#type, SendType::File);
        assert_eq!(result.send.auth_type, AuthType::None);

        // The created send should have been persisted to the repository.
        let stored: Option<Send> = repository
            .get(SendId::new(SEND_ID.parse().unwrap()))
            .await
            .unwrap();
        assert!(stored.is_some(), "send should be stored in the repository");
    }

    #[tokio::test]
    async fn test_create_file_send_errors_when_file_upload_type_missing() {
        let mock = Mock::given(method("POST"))
            .and(path("/sends/file/v2"))
            .respond_with(move |req: &wiremock::Request| {
                let body: bitwarden_api_api::models::SendRequestModel =
                    serde_json::from_slice(&req.body).unwrap();
                let send_response = echo_file_send_response(body);
                let response = SendFileUploadDataResponseModel {
                    object: Some("send-fileUpload".to_string()),
                    url: Some("https://upload.example.com/abc".to_string()),
                    // Omit file_upload_type — the SDK must not silently default to a
                    // backend that could route bytes to the wrong place.
                    file_upload_type: None,
                    send_response: Some(Box::new(send_response)),
                };
                ResponseTemplate::new(200).set_body_json(&response)
            });

        let (server, _config) = start_api_mock(vec![mock]).await;
        let (client, _repository) = make_test_client(&server);

        let err = client
            .sends()
            .create_file_send(sample_request())
            .await
            .unwrap_err();

        assert!(matches!(err, CreateFileSendError::MissingField(_)));
    }

    #[tokio::test]
    async fn test_create_file_send_http_error() {
        let mock = Mock::given(method("POST"))
            .and(path("/sends/file/v2"))
            .respond_with(ResponseTemplate::new(500));

        let (server, _config) = start_api_mock(vec![mock]).await;
        let (client, _repository) = make_test_client(&server);

        let err = client
            .sends()
            .create_file_send(sample_request())
            .await
            .unwrap_err();

        assert!(matches!(err, CreateFileSendError::Api(_)));
    }

    #[tokio::test]
    async fn test_create_file_send_empty_email_list_validation() {
        // No HTTP mock needed: validation should fail before the request is sent.
        let server = MockServer::start().await;
        let (client, _repository) = make_test_client(&server);

        let mut request = sample_request();
        request.auth = SendAuthType::Emails { emails: vec![] };

        let err = client.sends().create_file_send(request).await.unwrap_err();

        assert!(matches!(err, CreateFileSendError::EmptyEmailList(_)));
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "validation failure should short-circuit before any HTTP call"
        );
    }

    // ===== upload_send_file =====

    #[tokio::test]
    async fn test_upload_send_file() {
        let send_id = SendId::new(SEND_ID.parse().unwrap());
        let file_id = FILE_ID.to_string();
        let encrypted_file_name = "2.encrypted-name|abc|def".to_string();
        let data = b"encrypted-file-bytes".to_vec();

        let mock = Mock::given(method("POST"))
            .and(path(format!("/sends/{}/file/{}", SEND_ID, FILE_ID)))
            .respond_with(ResponseTemplate::new(200));

        let (server, _config) = start_api_mock(vec![mock]).await;
        let (client, _repository) = make_test_client(&server);

        client
            .sends()
            .upload_send_file(send_id, file_id, encrypted_file_name, data.clone())
            .await
            .unwrap();

        // Verify the multipart request looked right.
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let req = &requests[0];
        let content_type = req
            .headers
            .get("content-type")
            .map(|v| v.to_str().unwrap())
            .unwrap_or_default();
        assert!(
            content_type.starts_with("multipart/form-data"),
            "expected multipart/form-data, got {content_type}"
        );
        // The encrypted bytes should appear verbatim in the multipart body.
        let body = &req.body;
        assert!(
            body.windows(data.len()).any(|w| w == data.as_slice()),
            "request body should contain the encrypted file bytes"
        );
        // The form part name and file_name should be embedded in the multipart headers.
        let body_str = String::from_utf8_lossy(body);
        assert!(
            body_str.contains("name=\"data\""),
            "multipart should include the 'data' part name"
        );
        assert!(
            body_str.contains("filename=\"2.encrypted-name|abc|def\""),
            "multipart should include the encrypted file name as the part's filename"
        );
    }

    #[tokio::test]
    async fn test_upload_send_file_http_error() {
        let send_id = SendId::new(SEND_ID.parse().unwrap());
        let file_id = FILE_ID.to_string();

        let mock = Mock::given(method("POST"))
            .and(path(format!("/sends/{}/file/{}", SEND_ID, FILE_ID)))
            .respond_with(ResponseTemplate::new(500));

        let (server, _config) = start_api_mock(vec![mock]).await;
        let (client, _repository) = make_test_client(&server);

        let err = client
            .sends()
            .upload_send_file(
                send_id,
                file_id,
                "encrypted-name".to_string(),
                b"data".to_vec(),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, UploadSendFileError::Api(_)));
    }

    // ===== renew_file_upload_url =====

    #[tokio::test]
    async fn test_renew_file_upload_url() {
        let send_id = SendId::new(SEND_ID.parse().unwrap());
        let file_id = FILE_ID.to_string();
        let new_url = "https://upload.example.com/renewed";

        // The generated client issues a GET against /sends/{id}/file/{fileId}.
        let mock = Mock::given(method("GET"))
            .and(path_regex(r"^/sends/[a-f0-9-]+/file/[^/]+$"))
            .respond_with(move |req: &wiremock::Request| {
                // Sanity-check the path arguments were threaded through correctly.
                assert!(
                    req.url
                        .path()
                        .ends_with(&format!("/sends/{}/file/{}", SEND_ID, FILE_ID))
                );
                let response = SendFileUploadDataResponseModel {
                    object: Some("send-fileUpload".to_string()),
                    url: Some(new_url.to_string()),
                    file_upload_type: Some(FileUploadType::Azure),
                    send_response: None,
                };
                ResponseTemplate::new(200).set_body_json(&response)
            });

        let (server, _config) = start_api_mock(vec![mock]).await;
        let (client, _repository) = make_test_client(&server);

        let url = client
            .sends()
            .renew_file_upload_url(send_id, file_id)
            .await
            .unwrap();

        assert_eq!(url, new_url);
    }

    #[tokio::test]
    async fn test_renew_file_upload_url_missing_url() {
        let send_id = SendId::new(SEND_ID.parse().unwrap());
        let file_id = FILE_ID.to_string();

        // Server returns a 200 but omits the url field; this exercises the require!(resp.url)
        // branch which maps to MissingField.
        let mock = Mock::given(method("GET"))
            .and(path_regex(r"^/sends/[a-f0-9-]+/file/[^/]+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                &SendFileUploadDataResponseModel {
                    object: Some("send-fileUpload".to_string()),
                    url: None,
                    file_upload_type: None,
                    send_response: None,
                },
            ));

        let (server, _config) = start_api_mock(vec![mock]).await;
        let (client, _repository) = make_test_client(&server);

        let err = client
            .sends()
            .renew_file_upload_url(send_id, file_id)
            .await
            .unwrap_err();

        assert!(matches!(err, RenewFileUploadUrlError::MissingField(_)));
    }

    #[tokio::test]
    async fn test_renew_file_upload_url_http_error() {
        let send_id = SendId::new(SEND_ID.parse().unwrap());
        let file_id = FILE_ID.to_string();

        let mock = Mock::given(method("GET"))
            .and(path_regex(r"^/sends/[a-f0-9-]+/file/[^/]+$"))
            .respond_with(ResponseTemplate::new(500));

        let (server, _config) = start_api_mock(vec![mock]).await;
        let (client, _repository) = make_test_client(&server);

        let err = client
            .sends()
            .renew_file_upload_url(send_id, file_id)
            .await
            .unwrap_err();

        assert!(matches!(err, RenewFileUploadUrlError::Api(_)));
    }
}
