use std::sync::Arc;

use bitwarden_core::FromClient;
use bitwarden_state::repository::{Repository, RepositoryOption};
use bitwarden_sync::{SyncHandler, SyncHandlerError};

use crate::{PolicyId, PolicyView};

/// Sync handler for policies.
///
/// This handler persists organization policies to SDK-managed storage.
#[derive(FromClient)]
pub struct PolicySyncHandler {
    repository: Option<Arc<dyn Repository<PolicyView>>>,
}

#[async_trait::async_trait]
impl SyncHandler for PolicySyncHandler {
    async fn on_sync(
        &self,
        response: &bitwarden_api_api::models::SyncResponseModel,
    ) -> Result<(), SyncHandlerError> {
        let repository = self.repository.require()?;
        // Only `policiesNew` is used in rust. `policies` is deprecated.
        let api_policies = response
            .policies_new
            .as_ref()
            .ok_or_else(|| SyncHandlerError::from("Sync response contained no policies"))?;

        let policies: Vec<(PolicyId, PolicyView)> = api_policies
            .iter()
            .filter_map(|p| {
                PolicyView::try_from(p.clone())
                    .inspect_err(
                        |e| tracing::error!(id = ?p.id, error = ?e, "Failed to deserialize policy"),
                    )
                    .ok()
                    .map(|view| (view.id, view))
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
    use bitwarden_test::MemoryRepository;
    use uuid::Uuid;

    use super::*;

    fn make_policy_response(id: Uuid) -> PolicyResponseModel {
        PolicyResponseModel {
            id: Some(id),
            organization_id: Some(Uuid::new_v4()),
            r#type: Some(bitwarden_api_api::models::PolicyType::MasterPassword),
            data: Some(serde_json::json!({ "minLength": 12 })),
            enabled: Some(true),
            revision_date: Some("2025-01-01T00:00:00Z".to_string()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_on_sync_replaces_existing_policies() {
        let repository = Arc::new(MemoryRepository::<PolicyView>::default());
        let handler = PolicySyncHandler {
            repository: Some(repository.clone()),
        };

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let response = SyncResponseModel {
            policies_new: Some(vec![make_policy_response(id1), make_policy_response(id2)]),
            ..Default::default()
        };
        handler.on_sync(&response).await.unwrap();
        assert_eq!(repository.list().await.unwrap().len(), 2);

        // A subsequent sync with fewer policies fully replaces the stored set.
        let id3 = Uuid::new_v4();
        let response = SyncResponseModel {
            policies_new: Some(vec![make_policy_response(id3)]),
            ..Default::default()
        };
        handler.on_sync(&response).await.unwrap();

        let stored = repository.list().await.unwrap();
        assert_eq!(stored.len(), 1);
        assert!(repository.get(PolicyId::new(id1)).await.unwrap().is_none());
        assert!(repository.get(PolicyId::new(id3)).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_on_sync_no_policies_returns_error() {
        let repository = Arc::new(MemoryRepository::<PolicyView>::default());
        let handler = PolicySyncHandler {
            repository: Some(repository.clone()),
        };

        let response = SyncResponseModel::default();
        assert!(handler.on_sync(&response).await.is_err());
    }
}
