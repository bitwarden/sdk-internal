//! [`OrganizationsClient`] and its associated extension trait.

use std::sync::Arc;

use bitwarden_core::{Client, FromClient, OrganizationId};
use bitwarden_state::repository::{Repository, RepositoryError, RepositoryOption};

use crate::ProfileOrganization;

/// Client for reading the current user's organizations in sync data.
#[derive(FromClient)]
pub struct OrganizationsClient {
    pub(crate) repository: Option<Arc<dyn Repository<ProfileOrganization>>>,
}

impl OrganizationsClient {
    /// Get the organization with the given ID, or `None` if it does not exist or the user does not
    /// have access.
    pub async fn get_by_id(
        &self,
        organization_id: OrganizationId,
    ) -> Result<Option<ProfileOrganization>, RepositoryError> {
        self.repository.require()?.get(organization_id).await
    }

    /// Get all of the current user's organizations.
    pub async fn get_all(&self) -> Result<Vec<ProfileOrganization>, RepositoryError> {
        self.repository.require()?.list().await
    }
}

/// Extension trait to add the organizations client to the main Bitwarden SDK client.
pub trait OrganizationsClientExt {
    /// Get the organizations client.
    fn organizations(&self) -> OrganizationsClient;
}

impl OrganizationsClientExt for Client {
    fn organizations(&self) -> OrganizationsClient {
        OrganizationsClient::from_client(self)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_test::MemoryRepository;
    use uuid::Uuid;

    use super::*;
    use crate::OrganizationDetails;

    fn organization(id: OrganizationId, name: &str) -> ProfileOrganization {
        ProfileOrganization {
            details: OrganizationDetails {
                id,
                name: name.to_string(),
                ..OrganizationDetails::default()
            },
            ..ProfileOrganization::default()
        }
    }

    async fn client_with(organizations: &[ProfileOrganization]) -> OrganizationsClient {
        let repository = Arc::new(MemoryRepository::<ProfileOrganization>::default());
        for org in organizations {
            repository.set(org.details.id, org.clone()).await.unwrap();
        }
        OrganizationsClient {
            repository: Some(repository),
        }
    }

    #[tokio::test]
    async fn get_by_id_returns_matching_organization() {
        let id = OrganizationId::new(Uuid::new_v4());
        let other = OrganizationId::new(Uuid::new_v4());
        let client = client_with(&[organization(id, "Org"), organization(other, "Other")]).await;

        let result = client.get_by_id(id).await.unwrap();

        assert_eq!(result, Some(organization(id, "Org")));
    }

    #[tokio::test]
    async fn get_by_id_returns_none_when_missing() {
        let client = client_with(&[]).await;

        let result = client
            .get_by_id(OrganizationId::new(Uuid::new_v4()))
            .await
            .unwrap();

        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn get_all_returns_every_organization() {
        let first = organization(OrganizationId::new(Uuid::new_v4()), "First");
        let second = organization(OrganizationId::new(Uuid::new_v4()), "Second");
        let client = client_with(&[first.clone(), second.clone()]).await;

        let mut result = client.get_all().await.unwrap();
        result.sort_by(|a, b| a.details.name.cmp(&b.details.name));

        assert_eq!(result, vec![first, second]);
    }

    #[tokio::test]
    async fn errors_without_a_repository() {
        let client = OrganizationsClient { repository: None };

        assert!(client.get_all().await.is_err());
        assert!(
            client
                .get_by_id(OrganizationId::new(Uuid::new_v4()))
                .await
                .is_err()
        );
    }
}
