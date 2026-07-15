use bitwarden_api_api::{apis::ApiClient, models};
use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{SendParseError, SendType, send_client::SendClient};

// ===== Public output types (returned to callers) =====

/// View of a send's accessible content, returned after a successful send access call.
/// Name, text, and file fields are encrypted and must be decrypted client-side using the
/// key derived from the URL fragment.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi))]
pub struct SendAccessResponse {
    /// The send access ID
    pub id: Option<String>,
    /// The send type.
    #[serde(rename = "type")]
    pub type_: Option<SendType>,
    /// Encrypted send name
    pub name: Option<String>,
    /// Text content (if type is Text)
    pub text: Option<SendAccessTextResponse>,
    /// File metadata (if type is File)
    pub file: Option<SendAccessFileResponse>,
    /// When the send expires.
    pub expiration_date: Option<DateTime<Utc>>,
    /// The creator's identifier (email), if not hidden
    pub creator_identifier: Option<String>,
}

/// Encrypted text content of a text send.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi))]
pub struct SendAccessTextResponse {
    /// Encrypted text content
    pub text: Option<String>,
    /// Whether to hide the text by default
    pub hidden: bool,
}

/// Encrypted file metadata of a file send.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi))]
pub struct SendAccessFileResponse {
    /// The file ID
    pub id: Option<String>,
    /// Encrypted file name
    pub file_name: Option<String>,
    /// File size in bytes as a string
    pub size: Option<String>,
    /// Human-readable size (e.g. "4.2 KB")
    pub size_name: Option<String>,
}

/// File download URL data returned from a send file access call.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi))]
pub struct SendFileDownloadData {
    /// The file ID
    pub id: Option<String>,
    /// The pre-signed download URL
    pub url: Option<String>,
}

// ===== Error types =====

/// Error returned when accessing a send fails.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessSendError {
    /// An API or network error occurred.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// The response body could not be parsed into a [`SendAccessResponse`] — either a
    /// required field was missing, the send type was an unrecognized value, or a date
    /// field was malformed.
    #[error(transparent)]
    Parse(#[from] SendParseError),
}

/// Error returned when getting send file download data fails.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum GetFileDownloadDataError {
    /// An API or network error occurred.
    #[error(transparent)]
    Api(#[from] ApiError),
}

// ===== HTTP request functions =====

async fn access_send_v1(
    api_client: &ApiClient,
    send_id: &str,
    password: Option<String>,
) -> Result<SendAccessResponse, AccessSendError> {
    let resp = api_client
        .sends_api()
        .access(send_id, Some(models::SendAccessRequestModel { password }))
        .await?;
    Ok(resp.try_into()?)
}

async fn access_send(
    api_client: &ApiClient,
    access_token: &str,
) -> Result<SendAccessResponse, AccessSendError> {
    let resp = api_client
        .sends_api()
        .access_using_auth(access_token)
        .await?;
    Ok(resp.try_into()?)
}

async fn get_file_download_data_v1(
    api_client: &ApiClient,
    send_id: &str,
    file_id: &str,
    password: Option<String>,
) -> Result<SendFileDownloadData, GetFileDownloadDataError> {
    let resp = api_client
        .sends_api()
        .get_send_file_download_data(
            send_id,
            file_id,
            Some(models::SendAccessRequestModel { password }),
        )
        .await?;
    Ok(resp.into())
}

async fn get_file_download_data(
    api_client: &ApiClient,
    file_id: &str,
    access_token: &str,
) -> Result<SendFileDownloadData, GetFileDownloadDataError> {
    let resp = api_client
        .sends_api()
        .get_send_file_download_data_using_auth(file_id, access_token)
        .await?;
    Ok(resp.into())
}

// ===== Conversions from API response models =====

impl TryFrom<models::SendAccessResponseModel> for SendAccessResponse {
    type Error = SendParseError;

    fn try_from(r: models::SendAccessResponseModel) -> Result<Self, Self::Error> {
        Ok(SendAccessResponse {
            id: r.id,
            type_: r.r#type.map(SendType::try_from).transpose()?,
            name: r.name,
            text: r.text.map(|t| SendAccessTextResponse {
                text: t.text,
                hidden: t.hidden.unwrap_or(false),
            }),
            file: r.file.map(|f| SendAccessFileResponse {
                id: f.id,
                file_name: f.file_name,
                size: f.size,
                size_name: f.size_name,
            }),
            expiration_date: r.expiration_date.map(|s| s.parse()).transpose()?,
            creator_identifier: r.creator_identifier,
        })
    }
}

impl From<models::SendFileDownloadDataResponseModel> for SendFileDownloadData {
    fn from(r: models::SendFileDownloadDataResponseModel) -> Self {
        SendFileDownloadData {
            id: r.id,
            url: r.url,
        }
    }
}

// ===== SendClient methods =====

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl SendClient {
    /// Accesses a send using the V1 (legacy) API endpoint.
    /// The `password` is the SHA256 hash of the user-entered password, if the send is
    /// password-protected. The returned [SendAccessResponse] contains encrypted fields that must
    /// be decrypted client-side using the key derived from the URL fragment.
    pub async fn access_send_v1(
        &self,
        send_id: String,
        password: Option<String>,
    ) -> Result<SendAccessResponse, AccessSendError> {
        let config = self.client.internal.get_api_configurations();
        access_send_v1(&config.api_client, &send_id, password).await
    }

    /// Accesses a send using the V2 API endpoint, authenticated with a send access token.
    /// The returned [SendAccessResponse] contains encrypted fields that must be decrypted
    /// client-side using the key derived from the URL fragment.
    pub async fn access_send(
        &self,
        access_token: String,
    ) -> Result<SendAccessResponse, AccessSendError> {
        let config = self.client.internal.get_api_configurations();
        access_send(&config.api_client, &access_token).await
    }

    /// Gets file download data for a file send using the V1 (legacy) API endpoint.
    /// The `password` is the SHA256 hash of the user-entered password, if the send is
    /// password-protected.
    pub async fn get_file_download_data_v1(
        &self,
        send_id: String,
        file_id: String,
        password: Option<String>,
    ) -> Result<SendFileDownloadData, GetFileDownloadDataError> {
        let config = self.client.internal.get_api_configurations();
        get_file_download_data_v1(&config.api_client, &send_id, &file_id, password).await
    }

    /// Gets file download data for a file send using the V2 API endpoint, authenticated
    /// with a send access token.
    pub async fn get_file_download_data(
        &self,
        access_token: String,
        file_id: String,
    ) -> Result<SendFileDownloadData, GetFileDownloadDataError> {
        let config = self.client.internal.get_api_configurations();
        get_file_download_data(&config.api_client, &file_id, &access_token).await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            SendAccessResponseModel, SendFileDownloadDataResponseModel, SendFileModel,
            SendTextModel, SendType,
        },
    };

    use super::*;

    const SEND_ID: &str = "25afb11c-9c95-4db5-8bac-c21cb204a3f1";
    const FILE_ID: &str = "file-id-abc";
    const ACCESS_TOKEN: &str = "send-access-token";

    // ===== access_send_v1 =====

    #[tokio::test]
    async fn test_access_send_v1_text() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sends_api
                .expect_access()
                .returning(|id, request| {
                    assert_eq!(id, SEND_ID);
                    let request = request.expect("request body should be present");
                    assert_eq!(request.password, Some("hashed-password".to_string()));
                    Ok(SendAccessResponseModel {
                        object: Some("send-access".to_string()),
                        id: Some(SEND_ID.to_string()),
                        r#type: Some(SendType::Text),
                        auth_type: None,
                        name: Some("encrypted-name".to_string()),
                        file: None,
                        text: Some(Box::new(SendTextModel {
                            text: Some("encrypted-text".to_string()),
                            hidden: Some(true),
                        })),
                        expiration_date: Some("2025-01-10T00:00:00Z".to_string()),
                        creator_identifier: Some("user@example.com".to_string()),
                    })
                })
                .once();
        });

        let result = access_send_v1(&api_client, SEND_ID, Some("hashed-password".to_string()))
            .await
            .unwrap();

        assert_eq!(result.id, Some(SEND_ID.to_string()));
        assert_eq!(result.type_, Some(crate::SendType::Text));
        assert_eq!(result.name, Some("encrypted-name".to_string()));
        let text = result.text.expect("text variant should be populated");
        assert_eq!(text.text, Some("encrypted-text".to_string()));
        assert!(text.hidden);
        assert!(result.file.is_none());
        assert_eq!(
            result.expiration_date,
            Some("2025-01-10T00:00:00Z".parse::<DateTime<Utc>>().unwrap())
        );
        assert_eq!(
            result.creator_identifier,
            Some("user@example.com".to_string())
        );
    }

    #[tokio::test]
    async fn test_access_send_v1_http_error() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sends_api
                .expect_access()
                .returning(|_id, _request| {
                    Err(bitwarden_api_api::ApiError::Io(std::io::Error::other(
                        "Simulated error",
                    )))
                })
                .once();
        });

        let result = access_send_v1(&api_client, SEND_ID, None).await;

        assert!(matches!(result.unwrap_err(), AccessSendError::Api(_)));
    }

    // ===== access_send =====

    #[tokio::test]
    async fn test_access_send_file() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sends_api
                .expect_access_using_auth()
                .returning(|token| {
                    assert_eq!(token, ACCESS_TOKEN);
                    Ok(SendAccessResponseModel {
                        object: Some("send-access".to_string()),
                        id: Some(SEND_ID.to_string()),
                        r#type: Some(SendType::File),
                        auth_type: None,
                        name: Some("encrypted-name".to_string()),
                        file: Some(Box::new(SendFileModel {
                            id: Some(FILE_ID.to_string()),
                            file_name: Some("encrypted-file-name".to_string()),
                            size: Some("4200".to_string()),
                            size_name: Some("4.2 KB".to_string()),
                        })),
                        text: None,
                        expiration_date: None,
                        creator_identifier: None,
                    })
                })
                .once();
        });

        let result = access_send(&api_client, ACCESS_TOKEN).await.unwrap();

        assert_eq!(result.id, Some(SEND_ID.to_string()));
        assert_eq!(result.type_, Some(crate::SendType::File));
        assert_eq!(result.name, Some("encrypted-name".to_string()));
        assert!(result.text.is_none());
        let file = result.file.expect("file variant should be populated");
        assert_eq!(file.id, Some(FILE_ID.to_string()));
        assert_eq!(file.file_name, Some("encrypted-file-name".to_string()));
        assert_eq!(file.size, Some("4200".to_string()));
        assert_eq!(file.size_name, Some("4.2 KB".to_string()));
        assert_eq!(result.expiration_date, None);
        assert_eq!(result.creator_identifier, None);
    }

    #[tokio::test]
    async fn test_access_send_http_error() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sends_api
                .expect_access_using_auth()
                .returning(|_token| {
                    Err(bitwarden_api_api::ApiError::Io(std::io::Error::other(
                        "Simulated error",
                    )))
                })
                .once();
        });

        let result = access_send(&api_client, ACCESS_TOKEN).await;

        assert!(matches!(result.unwrap_err(), AccessSendError::Api(_)));
    }

    // ===== get_file_download_data_v1 =====

    #[tokio::test]
    async fn test_get_file_download_data_v1() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sends_api
                .expect_get_send_file_download_data()
                .returning(|send_id, file_id, request| {
                    assert_eq!(send_id, SEND_ID);
                    assert_eq!(file_id, FILE_ID);
                    let request = request.expect("request body should be present");
                    assert_eq!(request.password, Some("hashed-password".to_string()));
                    Ok(SendFileDownloadDataResponseModel {
                        object: Some("send-fileDownload".to_string()),
                        id: Some(FILE_ID.to_string()),
                        url: Some("https://example.com/download".to_string()),
                    })
                })
                .once();
        });

        let result = get_file_download_data_v1(
            &api_client,
            SEND_ID,
            FILE_ID,
            Some("hashed-password".to_string()),
        )
        .await
        .unwrap();

        assert_eq!(result.id, Some(FILE_ID.to_string()));
        assert_eq!(result.url, Some("https://example.com/download".to_string()));
    }

    #[tokio::test]
    async fn test_get_file_download_data_v1_http_error() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sends_api
                .expect_get_send_file_download_data()
                .returning(|_send_id, _file_id, _request| {
                    Err(bitwarden_api_api::ApiError::Io(std::io::Error::other(
                        "Simulated error",
                    )))
                })
                .once();
        });

        let result = get_file_download_data_v1(&api_client, SEND_ID, FILE_ID, None).await;

        assert!(matches!(
            result.unwrap_err(),
            GetFileDownloadDataError::Api(_)
        ));
    }

    // ===== get_file_download_data =====

    #[tokio::test]
    async fn test_get_file_download_data() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sends_api
                .expect_get_send_file_download_data_using_auth()
                .returning(|file_id, token| {
                    assert_eq!(file_id, FILE_ID);
                    assert_eq!(token, ACCESS_TOKEN);
                    Ok(SendFileDownloadDataResponseModel {
                        object: Some("send-fileDownload".to_string()),
                        id: Some(FILE_ID.to_string()),
                        url: Some("https://example.com/download".to_string()),
                    })
                })
                .once();
        });

        let result = get_file_download_data(&api_client, FILE_ID, ACCESS_TOKEN)
            .await
            .unwrap();

        assert_eq!(result.id, Some(FILE_ID.to_string()));
        assert_eq!(result.url, Some("https://example.com/download".to_string()));
    }

    #[tokio::test]
    async fn test_get_file_download_data_http_error() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sends_api
                .expect_get_send_file_download_data_using_auth()
                .returning(|_file_id, _token| {
                    Err(bitwarden_api_api::ApiError::Io(std::io::Error::other(
                        "Simulated error",
                    )))
                })
                .once();
        });

        let result = get_file_download_data(&api_client, FILE_ID, ACCESS_TOKEN).await;

        assert!(matches!(
            result.unwrap_err(),
            GetFileDownloadDataError::Api(_)
        ));
    }
}
