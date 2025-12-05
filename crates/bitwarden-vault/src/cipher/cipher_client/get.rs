use bitwarden_api_api::models::CipherMiniDetailsResponseModelListResponseModel;
use bitwarden_core::{ApiError, MissingFieldError, OrganizationId, key_management::KeyIds};
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;

use super::CiphersClient;
use crate::{
    Cipher, CipherView, ItemNotFoundError, VaultParseError, cipher::cipher::DecryptCipherListResult,
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum GetCipherError {
    #[error(transparent)]
    ItemNotFound(#[from] ItemNotFoundError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    RepositoryError(#[from] RepositoryError),
    #[error(transparent)]
    Api(#[from] ApiError),
}

async fn get_cipher(
    store: &KeyStore<KeyIds>,
    repository: &dyn Repository<Cipher>,
    id: &str,
) -> Result<CipherView, GetCipherError> {
    let cipher = repository
        .get(id.to_string())
        .await?
        .ok_or(ItemNotFoundError)?;

    Ok(store.decrypt(&cipher)?)
}

async fn list_ciphers(
    store: &KeyStore<KeyIds>,
    repository: &dyn Repository<Cipher>,
) -> Result<DecryptCipherListResult, GetCipherError> {
    let ciphers = repository.list().await?;
    let (successes, failures) = store.decrypt_list_with_failures(&ciphers);
    Ok(DecryptCipherListResult {
        successes,
        failures: failures.into_iter().cloned().collect(),
    })
}

impl CiphersClient {
    /// Get all ciphers from state and decrypt them, returning both successes and failures.
    /// This method will not fail when some ciphers fail to decrypt, allowing for graceful
    /// handling of corrupted or problematic cipher data.
    pub async fn list(&self) -> Result<DecryptCipherListResult, GetCipherError> {
        let key_store = self.client.internal.get_key_store();
        let repository = self.get_repository()?;

        list_ciphers(key_store, repository.as_ref()).await
    }

    /// Get all ciphers for an organization.
    pub async fn list_org_ciphers(
        &self,
        org_id: OrganizationId,
        include_member_items: bool,
    ) -> Result<DecryptCipherListResult, GetCipherError> {
        let configs = self.client.internal.get_api_configurations().await;
        let api = configs.api_client.ciphers_api();
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

        Ok(self.decrypt_list_with_failures(ciphers))
    }

    /// Get [Cipher] by ID from state and decrypt it to a [CipherView].
    pub async fn get(&self, cipher_id: &str) -> Result<CipherView, GetCipherError> {
        let key_store = self.client.internal.get_key_store();
        let repository = self.get_repository()?;

        get_cipher(key_store, repository.as_ref(), cipher_id).await
    }
}
