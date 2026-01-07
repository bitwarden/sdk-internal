use bitwarden_api_api::models::CipherMiniDetailsResponseModelListResponseModel;
use bitwarden_core::{ApiError, OrganizationId, key_management::KeyIds};
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    VaultParseError,
    cipher::cipher::{DecryptCipherListResult, PartialCipher},
    cipher_client::admin::CipherAdminClient,
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum GetOrganizationCiphersAdminError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    #[error(transparent)]
    Api(#[from] ApiError),
}

/// Get all ciphers for an organization.
pub async fn list_org_ciphers(
    org_id: OrganizationId,
    include_member_items: bool,
    api_client: &bitwarden_api_api::apis::ApiClient,
    key_store: &KeyStore<KeyIds>,
) -> Result<DecryptCipherListResult, GetOrganizationCiphersAdminError> {
    let api = api_client.ciphers_api();
    let response: CipherMiniDetailsResponseModelListResponseModel = api
        .get_organization_ciphers(Some(org_id.into()), Some(include_member_items))
        .await
        .map_err(ApiError::from)?;
    let ciphers = response
        .data
        .into_iter()
        .flatten()
        .map(|model| model.merge_with_cipher(None))
        .collect::<Result<Vec<_>, _>>()?;

    let (successes, failures) = key_store.decrypt_list_with_failures(&ciphers);
    Ok(DecryptCipherListResult {
        successes,
        failures: failures.into_iter().cloned().collect(),
    })
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CipherAdminClient {
    pub async fn list_org_ciphers(
        &self,
        org_id: OrganizationId,
        include_member_items: bool,
    ) -> Result<DecryptCipherListResult, GetOrganizationCiphersAdminError> {
        list_org_ciphers(
            org_id,
            include_member_items,
            &self
                .client
                .internal
                .get_api_configurations()
                .await
                .api_client,
            self.client.internal.get_key_store(),
        )
        .await
    }
}
