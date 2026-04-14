use std::sync::Arc;

use bitwarden_core::{FromClient, require};
use bitwarden_state::{registry::StateRegistryError, repository::Repository};
use bitwarden_sync::{SyncHandler, SyncHandlerError};
use uuid::Uuid;

use crate::Policy;

/// Sync handler for organization policies.
///
/// This handler persists policies to SDK-managed storage, following the same
/// pattern as [`FolderSyncHandler`](bitwarden_vault::FolderSyncHandler).
#[derive(FromClient)]
pub struct PolicySyncHandler {
    repository: Option<Arc<dyn Repository<Policy>>>,
}

#[async_trait::async_trait]
impl SyncHandler for PolicySyncHandler {
    async fn on_sync(
        &self,
        response: &bitwarden_api_api::models::SyncResponseModel,
    ) -> Result<(), SyncHandlerError> {
        let repository = self
            .repository
            .as_ref()
            .ok_or(StateRegistryError::DatabaseNotInitialized)?;
        let api_policies = require!(response.policies.as_ref());

        let policies: Vec<(Uuid, Policy)> = api_policies
            .iter()
            .filter_map(|p| {
                Policy::try_from(p.clone())
                    .inspect_err(|e| tracing::error!(error = ?e, "Failed to deserialize policy"))
                    .ok()
                    .map(|policy| (policy.id(), policy))
            })
            .collect();

        repository.replace_all(policies).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::models::{PolicyResponseModel, SyncResponseModel};
    use bitwarden_state::repository::Repository;
    use bitwarden_test::MemoryRepository;

    use super::*;

    fn make_policy_response(
        id: uuid::Uuid,
        policy_type: bitwarden_api_api::models::PolicyType,
        enabled: bool,
    ) -> PolicyResponseModel {
        PolicyResponseModel {
            object: Some("policy".to_string()),
            id: Some(id),
            organization_id: Some(uuid::Uuid::new_v4()),
            r#type: Some(policy_type),
            data: Some(std::collections::HashMap::new()),
            enabled: Some(enabled),
            revision_date: Some("2025-01-01T00:00:00Z".to_string()),
        }
    }

    #[tokio::test]
    async fn test_on_sync_replaces_existing_policies() {
        let repository: Arc<dyn Repository<Policy>> =
            Arc::new(MemoryRepository::<Policy>::default());
        let handler = PolicySyncHandler {
            repository: Some(repository.clone()),
        };

        // First sync with two policies
        let id1 = uuid::Uuid::new_v4();
        let id2 = uuid::Uuid::new_v4();
        let response = SyncResponseModel {
            policies: Some(vec![
                make_policy_response(
                    id1,
                    bitwarden_api_api::models::PolicyType::PasswordGenerator,
                    true,
                ),
                make_policy_response(
                    id2,
                    bitwarden_api_api::models::PolicyType::MasterPassword,
                    true,
                ),
            ]),
            ..Default::default()
        };
        handler.on_sync(&response).await.unwrap();
        assert_eq!(repository.list().await.unwrap().len(), 2);

        // Second sync with only one policy -- old ones should be gone
        let id3 = uuid::Uuid::new_v4();
        let response = SyncResponseModel {
            policies: Some(vec![make_policy_response(
                id3,
                bitwarden_api_api::models::PolicyType::PasswordGenerator,
                true,
            )]),
            ..Default::default()
        };
        handler.on_sync(&response).await.unwrap();

        let stored = repository.list().await.unwrap();
        assert_eq!(stored.len(), 1);
        assert!(repository.get(id1).await.unwrap().is_none());
        assert!(repository.get(id2).await.unwrap().is_none());
        assert!(repository.get(id3).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_on_sync_no_policies_returns_error() {
        let repository: Arc<dyn Repository<Policy>> =
            Arc::new(MemoryRepository::<Policy>::default());
        let handler = PolicySyncHandler {
            repository: Some(repository.clone()),
        };

        let response = SyncResponseModel::default();
        let result = handler.on_sync(&response).await;
        assert!(result.is_err());
    }
}
