use bitwarden_core::Client;

use crate::{
    error::SecretsManagerError,
    secrets::{
        create_secret, delete_secrets, get_secret, get_secrets_by_ids, list_secrets,
        list_secrets_by_project, sync_secrets, update_secret, SecretCreateRequest,
        SecretGetRequest, SecretIdentifiersByProjectRequest, SecretIdentifiersRequest,
        SecretIdentifiersResponse, SecretPutRequest, SecretResponse, SecretsDeleteRequest,
        SecretsDeleteResponse, SecretsGetRequest, SecretsResponse, SecretsSyncRequest,
        SecretsSyncResponse,
    },
};

pub struct ClientSecrets {
    client: Client,
}

impl ClientSecrets {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn get(
        &self,
        input: &SecretGetRequest,
    ) -> Result<SecretResponse, SecretsManagerError> {
        get_secret(&self.client, input).await
    }

    pub async fn get_by_ids(
        &self,
        input: SecretsGetRequest,
    ) -> Result<SecretsResponse, SecretsManagerError> {
        get_secrets_by_ids(&self.client, input).await
    }

    pub async fn create(
        &self,
        input: &SecretCreateRequest,
    ) -> Result<SecretResponse, SecretsManagerError> {
        create_secret(&self.client, input).await
    }

    pub async fn list(
        &self,
        input: &SecretIdentifiersRequest,
    ) -> Result<SecretIdentifiersResponse, SecretsManagerError> {
        list_secrets(&self.client, input).await
    }

    pub async fn list_by_project(
        &self,
        input: &SecretIdentifiersByProjectRequest,
    ) -> Result<SecretIdentifiersResponse, SecretsManagerError> {
        list_secrets_by_project(&self.client, input).await
    }

    pub async fn update(
        &self,
        input: &SecretPutRequest,
    ) -> Result<SecretResponse, SecretsManagerError> {
        update_secret(&self.client, input).await
    }

    pub async fn delete(
        &self,
        input: SecretsDeleteRequest,
    ) -> Result<SecretsDeleteResponse, SecretsManagerError> {
        delete_secrets(&self.client, input).await
    }

    pub async fn sync(
        &self,
        input: &SecretsSyncRequest,
    ) -> Result<SecretsSyncResponse, SecretsManagerError> {
        sync_secrets(&self.client, input).await
    }
}

pub trait ClientSecretsExt {
    fn secrets(&self) -> ClientSecrets;
}

impl ClientSecretsExt for Client {
    fn secrets(&self) -> ClientSecrets {
        ClientSecrets::new(self.clone())
    }
}
