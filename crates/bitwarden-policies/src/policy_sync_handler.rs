use std::sync::Arc;

use bitwarden_core::{FromClient, require};
use bitwarden_state::repository::{Repository, RepositoryOption};
use bitwarden_sync::{SyncHandler, SyncHandlerError};

use crate::{Policy, PolicyId};

/// Sync handler for policies
///
/// This handler persists organization policies to SDK-managed storage.
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
        let repository = self.repository.require()?;
        // Prefer `policies_new` (policies for orgs where the user is confirmed/accepted),
        // falling back to the legacy `policies` (confirmed only) for older servers.
        let api_policies = require!(
            response
                .policies_new
                .as_ref()
                .or(response.policies.as_ref())
        );

        let policies: Vec<(PolicyId, Policy)> = api_policies
            .iter()
            .filter_map(|p| {
                Policy::try_from(p.clone())
                    .inspect_err(
                        |e| tracing::error!(id = ?p.id, error = ?e, "Failed to deserialize policy"),
                    )
                    .ok()
                    .map(|policy| (policy.id, policy))
            })
            .collect();

        repository.replace_all(policies).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::models::{PolicyResponseModel, PolicyType, SyncResponseModel};
    use bitwarden_test::MemoryRepository;

    use super::*;

    fn make_policy_response(id: uuid::Uuid, r#type: PolicyType) -> PolicyResponseModel {
        PolicyResponseModel {
            object: Some("policy".to_string()),
            id: Some(id),
            organization_id: Some(uuid::Uuid::new_v4()),
            r#type: Some(r#type),
            data: None,
            enabled: Some(true),
            revision_date: Some("2025-01-01T00:00:00Z".to_string()),
        }
    }

    #[tokio::test]
    async fn test_on_sync_replaces_existing_policies() {
        let repository = Arc::new(MemoryRepository::<Policy>::default());
        let handler = PolicySyncHandler {
            repository: Some(repository.clone()),
        };

        // First sync with two policies
        let id1 = uuid::Uuid::new_v4();
        let id2 = uuid::Uuid::new_v4();
        let response = SyncResponseModel {
            policies_new: Some(vec![
                make_policy_response(id1, PolicyType::MasterPassword),
                make_policy_response(id2, PolicyType::SingleOrg),
            ]),
            ..Default::default()
        };
        handler.on_sync(&response).await.unwrap();
        assert_eq!(repository.list().await.unwrap().len(), 2);

        // Second sync with only one policy — old ones should be gone
        let id3 = uuid::Uuid::new_v4();
        let response = SyncResponseModel {
            policies_new: Some(vec![make_policy_response(id3, PolicyType::RequireSso)]),
            ..Default::default()
        };
        handler.on_sync(&response).await.unwrap();

        let stored = repository.list().await.unwrap();
        assert_eq!(stored.len(), 1);
        assert!(repository.get(PolicyId::new(id1)).await.unwrap().is_none());
        assert!(repository.get(PolicyId::new(id2)).await.unwrap().is_none());
        assert!(repository.get(PolicyId::new(id3)).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_on_sync_falls_back_to_legacy_policies() {
        let repository = Arc::new(MemoryRepository::<Policy>::default());
        let handler = PolicySyncHandler {
            repository: Some(repository.clone()),
        };

        let id = uuid::Uuid::new_v4();
        let response = SyncResponseModel {
            policies: Some(vec![make_policy_response(id, PolicyType::MasterPassword)]),
            ..Default::default()
        };
        handler.on_sync(&response).await.unwrap();

        assert!(repository.get(PolicyId::new(id)).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_on_sync_skips_unknown_policy_type() {
        let repository = Arc::new(MemoryRepository::<Policy>::default());
        let handler = PolicySyncHandler {
            repository: Some(repository.clone()),
        };

        let known_id = uuid::Uuid::new_v4();
        let unknown_id = uuid::Uuid::new_v4();
        let response = SyncResponseModel {
            policies_new: Some(vec![
                make_policy_response(known_id, PolicyType::MasterPassword),
                make_policy_response(unknown_id, PolicyType::__Unknown(9999)),
            ]),
            ..Default::default()
        };
        handler.on_sync(&response).await.unwrap();

        // The unknown-typed policy is dropped; the valid one persists.
        let stored = repository.list().await.unwrap();
        assert_eq!(stored.len(), 1);
        assert!(
            repository
                .get(PolicyId::new(known_id))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            repository
                .get(PolicyId::new(unknown_id))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_on_sync_no_policies_returns_error() {
        let repository = Arc::new(MemoryRepository::<Policy>::default());
        let handler = PolicySyncHandler {
            repository: Some(repository.clone()),
        };

        let response = SyncResponseModel::default();
        let result = handler.on_sync(&response).await;
        assert!(result.is_err());
    }
}
