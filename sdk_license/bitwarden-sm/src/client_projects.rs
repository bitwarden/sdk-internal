use bitwarden_core::Client;

use crate::{
    error::SecretsManagerError,
    projects::{
        ProjectCreateRequest, ProjectGetRequest, ProjectPutRequest, ProjectResponse,
        ProjectsDeleteRequest, ProjectsDeleteResponse, ProjectsListRequest, ProjectsResponse,
        create_project, delete_projects, get_project, list_projects, update_project,
    },
};

/// Aliases to maintain backward compatibility
pub type ClientProjects = ProjectsClient;

#[allow(missing_docs)]
pub struct ProjectsClient {
    pub client: Client,
}

impl ProjectsClient {
    #[allow(missing_docs)]
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    #[allow(missing_docs)]
    pub async fn get(
        &self,
        input: &ProjectGetRequest,
    ) -> Result<ProjectResponse, SecretsManagerError> {
        get_project(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn create(
        &self,
        input: &ProjectCreateRequest,
    ) -> Result<ProjectResponse, SecretsManagerError> {
        create_project(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn list(
        &self,
        input: &ProjectsListRequest,
    ) -> Result<ProjectsResponse, SecretsManagerError> {
        list_projects(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn update(
        &self,
        input: &ProjectPutRequest,
    ) -> Result<ProjectResponse, SecretsManagerError> {
        update_project(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn delete(
        &self,
        input: ProjectsDeleteRequest,
    ) -> Result<ProjectsDeleteResponse, SecretsManagerError> {
        delete_projects(&self.client, input).await
    }
}

/// This trait is for backward compatibility
pub trait ClientProjectsExt {
    #[allow(missing_docs)]
    fn projects(&self) -> ClientProjects;
}

impl ClientProjectsExt for Client {
    fn projects(&self) -> ClientProjects {
        ProjectsClient::new(self.clone())
    }
}

#[allow(missing_docs)]
pub trait ProjectsClientExt {
    #[allow(missing_docs)]
    fn projects(&self) -> ProjectsClient;
}

impl ProjectsClientExt for Client {
    fn projects(&self) -> ProjectsClient {
        ProjectsClient::new(self.clone())
    }
}
