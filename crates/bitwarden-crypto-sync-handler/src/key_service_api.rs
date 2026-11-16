//! Reads the user's own keys and unlock methods from the Key Service API.
//!
//! The endpoints are not in the generated `bitwarden-api-api` bindings yet, so the requests and
//! wire models are written by hand here.
//!
//! ```text
//! GET /v1/keys/own        {"data":[{"id","type":"private-key","attributes":{"keyPurpose",...,"data":"{..}"}}]}
//! GET /v1/unlock-methods  {"data":[{"id","type":"unlock-method","attributes":{"kind",...,"data":"{..}"}}]}
//! ```

use bitwarden_api_base::{AuthRequired, Configuration};
use serde::{Deserialize, de::DeserializeOwned};

pub(crate) const OWN_KEYS_PATH: &str = "/v1/keys/own";
pub(crate) const UNLOCK_METHODS_PATH: &str = "/v1/unlock-methods";

/// Errors returned when a Key Service request fails.
#[derive(Debug, thiserror::Error)]
pub enum KeyServiceApiError {
    /// The request could not be sent, or its response could not be read.
    #[error("Key Service request failed")]
    Request(#[from] reqwest_middleware::Error),
    /// The response body could not be read.
    #[error("Key Service response could not be read")]
    Body(#[from] reqwest::Error),
    /// The server answered with a non-success status.
    #[error("Key Service responded with status {0}")]
    Status(reqwest::StatusCode),
    /// The response body is not the expected JSON document.
    #[error("Key Service response is malformed")]
    Malformed(#[from] serde_json::Error),
}

/// A Key Service response document: `{"data": ...}`.
#[derive(Deserialize, Debug)]
struct Document<T> {
    data: T,
}

/// A Key Service resource: `{"id": ..., "type": ..., "attributes": ...}`.
#[derive(Deserialize, Debug)]
pub(crate) struct Resource<T> {
    #[serde(rename = "type")]
    pub(crate) resource_type: String,
    pub(crate) attributes: T,
}

/// A key the user owns, e.g. their private key, signing key, security state or KDF settings.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OwnKeyAttributes {
    /// The key id of the encryption root sealing this key, when it is sealed by one.
    pub(crate) sealed_by_key_id: Option<String>,
    /// The key as a JSON string, whose shape depends on the resource type.
    pub(crate) data: String,
}

/// A way for the user to reach their encryption root, e.g. a master password.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UnlockMethodAttributes {
    /// The kind of unlock method, e.g. `master-password`.
    pub(crate) kind: String,
    /// The key id of the encryption root the method unlocks.
    pub(crate) contained_key_id: Option<String>,
    /// The unlock data as a JSON string, whose shape depends on the kind.
    pub(crate) data: String,
}

/// Reads the user's own keys.
pub(crate) async fn get_own_keys(
    configuration: &Configuration,
) -> Result<Vec<Resource<OwnKeyAttributes>>, KeyServiceApiError> {
    get(configuration, OWN_KEYS_PATH).await
}

/// Reads the user's unlock methods.
pub(crate) async fn get_unlock_methods(
    configuration: &Configuration,
) -> Result<Vec<Resource<UnlockMethodAttributes>>, KeyServiceApiError> {
    get(configuration, UNLOCK_METHODS_PATH).await
}

async fn get<T: DeserializeOwned>(
    configuration: &Configuration,
    path: &str,
) -> Result<T, KeyServiceApiError> {
    let response = configuration
        .client
        .get(format!("{}{path}", configuration.base_path))
        .header(reqwest::header::ACCEPT, "application/json")
        .with_extension(AuthRequired::Bearer)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        return Err(KeyServiceApiError::Status(status));
    }

    let body = response.text().await?;
    let document: Document<T> = serde_json::from_str(&body)?;
    Ok(document.data)
}
