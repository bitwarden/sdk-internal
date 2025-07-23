use bitwarden_api_api::{
    apis::accounts_key_management_api::accounts_key_management_regenerate_keys_post,
    models::KeyRegenerationRequestModel,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{ApiError, Client};

/// A client for the crypto operations.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct KeyManagementApiClient {
    pub(crate) client: crate::Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl KeyManagementApiClient {
    /// Performs API request to `accounts/key-management/regenerate-keys`.
    pub async fn accounts_key_management_regenerate_keys_post(
        &self,
        req: KeyRegenerationRequest,
    ) -> Result<(), ApiError> {
        let config = self.client.internal.get_api_configurations().await;
        Ok(accounts_key_management_regenerate_keys_post(&config.api, Some(req.into())).await?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct KeyRegenerationRequest {
    user_public_key: String,
    user_key_encrypted_user_private_key: String,
}

impl From<KeyRegenerationRequest> for KeyRegenerationRequestModel {
    fn from(req: KeyRegenerationRequest) -> Self {
        KeyRegenerationRequestModel {
            user_public_key: Some(req.user_public_key),
            user_key_encrypted_user_private_key: Some(req.user_key_encrypted_user_private_key),
        }
    }
}

impl Client {
    /// Temporary client for performing API requests for key management endpoints.
    pub fn km_api(&self) -> KeyManagementApiClient {
        KeyManagementApiClient {
            client: self.clone(),
        }
    }
}
