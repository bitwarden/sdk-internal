use std::sync::Arc;

use bitwarden_core::{FromClient, require};
use bitwarden_state::repository::{Repository, RepositoryOption};
use bitwarden_sync::{SyncHandler, SyncHandlerError};

use crate::{Send, SendId};

/// Sync handler for sends
///
/// This handler persists sends to SDK-managed storage.
#[derive(FromClient)]
pub struct SendSyncHandler {
    repository: Option<Arc<dyn Repository<Send>>>,
}

#[async_trait::async_trait]
impl SyncHandler for SendSyncHandler {
    async fn on_sync(
        &self,
        response: &bitwarden_api_api::models::SyncResponseModel,
    ) -> Result<(), SyncHandlerError> {
        let repository = self.repository.require()?;
        let api_sends = require!(response.sends.as_ref());

        let sends: Vec<(SendId, Send)> = api_sends
            .iter()
            .filter_map(|s| {
                Send::try_from(s.clone())
                    .inspect_err(
                        |e| tracing::error!(id = ?s.id, error = ?e, "Failed to deserialize send"),
                    )
                    .ok()
                    .and_then(|send| {
                        let id = send.id.or_else(|| {
                            tracing::error!("Skipping send with missing id");
                            None
                        })?;
                        Some((id, send))
                    })
            })
            .collect();

        repository.replace_all(sends).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::models::{SendResponseModel, SyncResponseModel};
    use bitwarden_test::MemoryRepository;

    use super::*;

    /// Valid EncString in type 2 format (Aes256CbcHmac): `2.<iv>|<data>|<mac>`
    const ENCRYPTED_STRING: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn make_send_response(id: uuid::Uuid) -> SendResponseModel {
        SendResponseModel {
            object: Some("send".to_string()),
            id: Some(id),
            access_id: None,
            r#type: Some(bitwarden_api_api::models::SendType::Text),
            auth_type: Some(bitwarden_api_api::models::AuthType::None),
            name: Some(ENCRYPTED_STRING.to_string()),
            notes: None,
            file: None,
            text: None,
            data: None,
            key: Some(ENCRYPTED_STRING.to_string()),
            max_access_count: None,
            access_count: Some(0),
            password: None,
            emails: None,
            disabled: Some(false),
            expiration_date: None,
            deletion_date: Some("2025-01-10T00:00:00Z".to_string()),
            revision_date: Some("2025-01-01T00:00:00Z".to_string()),
            hide_email: Some(false),
        }
    }

    #[tokio::test]
    async fn test_on_sync_replaces_existing_sends() {
        let repository = Arc::new(MemoryRepository::<Send>::default());
        let handler = SendSyncHandler {
            repository: Some(repository.clone()),
        };

        // First sync with two sends
        let id1 = uuid::Uuid::new_v4();
        let id2 = uuid::Uuid::new_v4();
        let response = SyncResponseModel {
            sends: Some(vec![make_send_response(id1), make_send_response(id2)]),
            ..Default::default()
        };
        handler.on_sync(&response).await.unwrap();
        assert_eq!(repository.list().await.unwrap().len(), 2);

        // Second sync with only one send — old ones should be gone
        let id3 = uuid::Uuid::new_v4();
        let response = SyncResponseModel {
            sends: Some(vec![make_send_response(id3)]),
            ..Default::default()
        };
        handler.on_sync(&response).await.unwrap();

        let stored = repository.list().await.unwrap();
        assert_eq!(stored.len(), 1);
        assert!(repository.get(SendId::new(id1)).await.unwrap().is_none());
        assert!(repository.get(SendId::new(id2)).await.unwrap().is_none());
        assert!(repository.get(SendId::new(id3)).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_on_sync_no_sends_returns_error() {
        let repository = Arc::new(MemoryRepository::<Send>::default());
        let handler = SendSyncHandler {
            repository: Some(repository.clone()),
        };

        let response = SyncResponseModel::default();
        let result = handler.on_sync(&response).await;
        assert!(result.is_err());
    }
}
