use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::send_client::SendClient;

// ===== Request body for V1 (password-protected sends) =====

#[derive(Debug, Serialize, Default)]
struct SendAccessRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
}

// ===== Raw API response types (fields may be encrypted) =====

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendAccessApiResponse {
    id: Option<String>,
    #[serde(rename = "type")]
    type_: Option<i32>,
    name: Option<String>,
    text: Option<SendAccessTextApiResponse>,
    file: Option<SendAccessFileApiResponse>,
    expiration_date: Option<String>,
    creator_identifier: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendAccessTextApiResponse {
    text: Option<String>,
    hidden: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendAccessFileApiResponse {
    id: Option<String>,
    file_name: Option<String>,
    size: Option<String>,
    size_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendFileDownloadDataApiResponse {
    id: Option<String>,
    url: Option<String>,
}

// ===== Public output types (returned to callers) =====

/// View of a send's accessible content, returned after a successful send access call.
/// Name, text, and file fields are encrypted and must be decrypted client-side using the
/// key derived from the URL fragment.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi))]
pub struct SendAccessView {
    /// The send access ID
    pub id: Option<String>,
    /// The send type (0 = Text, 1 = File)
    #[serde(rename = "type")]
    pub type_: Option<i32>,
    /// Encrypted send name
    pub name: Option<String>,
    /// Text content (if type is Text)
    pub text: Option<SendAccessTextView>,
    /// File metadata (if type is File)
    pub file: Option<SendAccessFileView>,
    /// When the send expires
    pub expiration_date: Option<String>,
    /// The creator's identifier (email), if not hidden
    pub creator_identifier: Option<String>,
}

/// Encrypted text content of a text send.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi))]
pub struct SendAccessTextView {
    /// Encrypted text content
    pub text: Option<String>,
    /// Whether to hide the text by default
    pub hidden: bool,
}

/// Encrypted file metadata of a file send.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi))]
pub struct SendAccessFileView {
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

/// POST /sends/access/{id} — V1 (legacy) send access, using Send-Id header.
/// The `password` is the SHA256 hash of the user-entered password, if the send is
/// password-protected.
async fn access_send_v1(
    api_config: &bitwarden_api_api::Configuration,
    send_id: &str,
    password: Option<String>,
) -> Result<SendAccessView, AccessSendError> {
    let url = format!("{}/sends/access/{}", api_config.base_path, send_id);
    let body = SendAccessRequestBody { password };

    let response = api_config
        .client
        .post(&url)
        .header("Send-Id", send_id)
        .json(&body)
        .send()
        .await
        .map_err(ApiError::from)?;

    let status = response.status();
    if !status.is_success() {
        let message = response.text().await.unwrap_or_default();
        return Err(ApiError::ResponseContent { status, message }.into());
    }

    let raw: SendAccessApiResponse = response.json().await.map_err(ApiError::from)?;
    Ok(raw.into())
}

/// POST /sends/access — V2 send access, using Authorization Bearer token.
async fn access_send(
    api_config: &bitwarden_api_api::Configuration,
    access_token: &str,
) -> Result<SendAccessView, AccessSendError> {
    let url = format!("{}/sends/access", api_config.base_path);

    let response = api_config
        .client
        .post(&url)
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", access_token),
        )
        .send()
        .await
        .map_err(ApiError::from)?;

    let status = response.status();
    if !status.is_success() {
        let message = response.text().await.unwrap_or_default();
        return Err(ApiError::ResponseContent { status, message }.into());
    }

    let raw: SendAccessApiResponse = response.json().await.map_err(ApiError::from)?;
    Ok(raw.into())
}

/// POST /sends/{sendId}/access/file/{fileId} — V1 (legacy) file download data, using Send-Id
/// header.
async fn get_file_download_data_v1(
    api_config: &bitwarden_api_api::Configuration,
    send_id: &str,
    file_id: &str,
    password: Option<String>,
) -> Result<SendFileDownloadData, GetFileDownloadDataError> {
    let url = format!(
        "{}/sends/{}/access/file/{}",
        api_config.base_path, send_id, file_id
    );
    let body = SendAccessRequestBody { password };

    let response = api_config
        .client
        .post(&url)
        .header("Send-Id", send_id)
        .json(&body)
        .send()
        .await
        .map_err(ApiError::from)?;

    let status = response.status();
    if !status.is_success() {
        let message = response.text().await.unwrap_or_default();
        return Err(ApiError::ResponseContent { status, message }.into());
    }

    let raw: SendFileDownloadDataApiResponse = response.json().await.map_err(ApiError::from)?;
    Ok(raw.into())
}

/// POST /sends/access/file/{fileId} — V2 file download data, using Authorization Bearer token.
async fn get_file_download_data(
    api_config: &bitwarden_api_api::Configuration,
    access_token: &str,
    file_id: &str,
) -> Result<SendFileDownloadData, GetFileDownloadDataError> {
    let url = format!("{}/sends/access/file/{}", api_config.base_path, file_id);

    let response = api_config
        .client
        .post(&url)
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", access_token),
        )
        .send()
        .await
        .map_err(ApiError::from)?;

    let status = response.status();
    if !status.is_success() {
        let message = response.text().await.unwrap_or_default();
        return Err(ApiError::ResponseContent { status, message }.into());
    }

    let raw: SendFileDownloadDataApiResponse = response.json().await.map_err(ApiError::from)?;
    Ok(raw.into())
}

// ===== Conversions from raw API responses =====

impl From<SendAccessApiResponse> for SendAccessView {
    fn from(r: SendAccessApiResponse) -> Self {
        SendAccessView {
            id: r.id,
            type_: r.type_,
            name: r.name,
            text: r.text.map(|t| SendAccessTextView {
                text: t.text,
                hidden: t.hidden.unwrap_or(false),
            }),
            file: r.file.map(|f| SendAccessFileView {
                id: f.id,
                file_name: f.file_name,
                size: f.size,
                size_name: f.size_name,
            }),
            expiration_date: r.expiration_date,
            creator_identifier: r.creator_identifier,
        }
    }
}

impl From<SendFileDownloadDataApiResponse> for SendFileDownloadData {
    fn from(r: SendFileDownloadDataApiResponse) -> Self {
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
    /// password-protected. The returned [SendAccessView] contains encrypted fields that must
    /// be decrypted client-side using the key derived from the URL fragment.
    pub async fn access_send_v1(
        &self,
        send_id: String,
        password: Option<String>,
    ) -> Result<SendAccessView, AccessSendError> {
        let configurations = self.client.internal.get_api_configurations();
        access_send_v1(&configurations.api_config, &send_id, password).await
    }

    /// Accesses a send using the V2 API endpoint, authenticated with a send access token.
    /// The returned [SendAccessView] contains encrypted fields that must be decrypted
    /// client-side using the key derived from the URL fragment.
    pub async fn access_send(
        &self,
        access_token: String,
    ) -> Result<SendAccessView, AccessSendError> {
        let configurations = self.client.internal.get_api_configurations();
        access_send(&configurations.api_config, &access_token).await
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
        let configurations = self.client.internal.get_api_configurations();
        get_file_download_data_v1(&configurations.api_config, &send_id, &file_id, password).await
    }

    /// Gets file download data for a file send using the V2 API endpoint, authenticated
    /// with a send access token.
    pub async fn get_file_download_data(
        &self,
        access_token: String,
        file_id: String,
    ) -> Result<SendFileDownloadData, GetFileDownloadDataError> {
        let configurations = self.client.internal.get_api_configurations();
        get_file_download_data(&configurations.api_config, &access_token, &file_id).await
    }
}
