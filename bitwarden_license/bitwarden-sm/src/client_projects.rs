use bitwarden_core::Client;

use crate::{
    error::SecretsManagerError,
    projects::{
        create_project, delete_projects, get_project, list_projects, update_project,
        ProjectCreateRequest, ProjectGetRequest, ProjectPutRequest, ProjectResponse,
        ProjectsDeleteRequest, ProjectsDeleteResponse, ProjectsListRequest, ProjectsResponse,
    },
};

pub struct ClientProjects {
    pub client: Client,
}

impl ClientProjects {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn get(
        &self,
        input: &ProjectGetRequest,
    ) -> Result<ProjectResponse, SecretsManagerError> {
        get_project(&self.client, input).await
    }

    pub async fn create(
        &self,
        input: &ProjectCreateRequest,
    ) -> Result<ProjectResponse, SecretsManagerError> {
        create_project(&self.client, input).await
    }

    pub async fn list(
        &self,
        input: &ProjectsListRequest,
    ) -> Result<ProjectsResponse, SecretsManagerError> {
        list_projects(&self.client, input).await
    }

    pub async fn update(
        &self,
        input: &ProjectPutRequest,
    ) -> Result<ProjectResponse, SecretsManagerError> {
        update_project(&self.client, input).await
    }

    pub async fn delete(
        &self,
        input: ProjectsDeleteRequest,
    ) -> Result<ProjectsDeleteResponse, SecretsManagerError> {
        delete_projects(&self.client, input).await
    }
}

pub trait ClientProjectsExt {
    fn projects(&self) -> ClientProjects;
}

impl ClientProjectsExt for Client {
    fn projects(&self) -> ClientProjects {
        ClientProjects::new(self.clone())
    }
}
