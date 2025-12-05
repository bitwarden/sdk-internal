use bitwarden_api_api::models::CipherMiniDetailsResponseModelListResponseModel;
use bitwarden_core::{ApiError, OrganizationId, key_management::KeyIds};
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::{
    Cipher, VaultParseError, cipher::cipher::DecryptCipherListResult,
    cipher_client::admin::CipherAdminClient,
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum GetOrganizationCiphersError {
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
) -> Result<DecryptCipherListResult, GetOrganizationCiphersError> {
    let api = api_client.ciphers_api();
    let response: CipherMiniDetailsResponseModelListResponseModel = api
        .get_organization_ciphers(Some(org_id.into()), Some(include_member_items))
        .await
        .map_err(Into::<ApiError>::into)?;
    let ciphers = response
        .data
        .into_iter()
        .flatten()
        .map(TryInto::<Cipher>::try_into)
        .collect::<Result<Vec<_>, _>>()?;

    let (successes, failures) = key_store.decrypt_list_with_failures(&ciphers);
    Ok(DecryptCipherListResult {
        successes,
        failures: failures.into_iter().cloned().collect(),
    })
}

impl CipherAdminClient {
    pub async fn list_org_ciphers(
        &self,
        org_id: OrganizationId,
        include_member_items: bool,
    ) -> Result<DecryptCipherListResult, GetOrganizationCiphersError> {
        list_org_ciphers(
            org_id,
            include_member_items,
            &self
                .client
                .internal
                .get_api_configurations()
                .await
                .api_client,
            &self.client.internal.get_key_store(),
        )
        .await
    }
}
