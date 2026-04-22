use bitwarden_api_base::AuthRequired;
use bitwarden_core::{ApiError, MissingFieldError, require};
use bitwarden_crypto::CryptoError;
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::RepositoryError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    EmptyEmailListError, Send, SendAddRequest, SendId, SendParseError, SendView,
    send_client::SendClient,
};

/// View returned after creating a file send.
///
/// Contains the created send and information needed to upload the file data.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi))]
pub struct CreateFileSendView {
    /// The created send.
    pub send: SendView,
    /// The upload URL for the file data.
    pub url: String,
    /// The file upload type (0 = Direct to Bitwarden server, 1 = Azure Blob Storage).
    pub file_upload_type: i32,
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
    ) -> Result<CreateFileSendView, CreateFileSendError> {
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
        let file_upload_type = resp
            .file_upload_type
            .map(|t| t.as_i64() as i32)
            .unwrap_or(0);
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

        let send_id = require!(send.id);
        repository.set(send_id, send.clone()).await?;

        let send_view = key_store.decrypt(&send)?;

        Ok(CreateFileSendView {
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
    /// `encrypted_file_name` is the encrypted file name string from [`CreateFileSendView`].
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
