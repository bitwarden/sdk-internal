use std::sync::Arc;

use bitwarden_core::{Client, FromClient, require};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError, RepositoryOption};
use bitwarden_sync::{SyncHandler, SyncHandlerError};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{Send, SendClientExt as _, SendId};

/// Persists `sends`, dropping any with a missing id (logged, not fatal).
async fn replace_sends(
    repository: Arc<dyn Repository<Send>>,
    sends: Vec<Send>,
) -> Result<(), RepositoryError> {
    let sends: Vec<(SendId, Send)> = sends
        .into_iter()
        .filter_map(|send| {
            let id = send.id.or_else(|| {
                tracing::error!("Skipping send with missing id");
                None
            })?;
            Some((id, send))
        })
        .collect();

    repository.replace_all(sends).await
}

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
        let repository = self.repository.require()?.clone();
        let api_sends = require!(response.sends.as_ref());

        let sends: Vec<Send> = api_sends
            .iter()
            .filter_map(|s| {
                Send::try_from(s.clone())
                    .inspect_err(
                        |e| tracing::error!(id = ?s.id, error = ?e, "Failed to deserialize send"),
                    )
                    .ok()
            })
            .collect();

        replace_sends(repository, sends).await?;

        Ok(())
    }
}

/// Errors returned by [`SendSyncHandlerClient::on_sync`].
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum SendSyncError {
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Client for the Send sync handler, for callers that fetch sync data themselves (e.g. the Web
/// client) and only want the Send-persistence part of a sync run.
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[bitwarden_ffi::wasm_object]
pub struct SendSyncHandlerClient {
    client: Client,
}

impl SendSyncHandlerClient {
    fn new(client: Client) -> Self {
        Self { client }
    }
}

#[bitwarden_ffi::wasm_export]
#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
impl SendSyncHandlerClient {
    /// Persists the sends from a sync response. Call this after each sync.
    pub async fn on_sync(&self, sends: Vec<Send>) -> Result<(), SendSyncError> {
        let repository = self.client.sends().get_repository()?;
        Ok(replace_sends(repository, sends).await?)
    }
}

/// Extension trait to add the Send sync handler client to the main Bitwarden SDK client.
pub trait SendSyncHandlerClientExt {
    /// Get the Send sync handler client.
    fn send_sync_handler(&self) -> SendSyncHandlerClient;
}

impl SendSyncHandlerClientExt for Client {
    fn send_sync_handler(&self) -> SendSyncHandlerClient {
        SendSyncHandlerClient::new(self.clone())
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

    fn test_send(id: uuid::Uuid) -> Send {
        Send {
            id: Some(SendId::new(id)),
            access_id: None,
            r#type: crate::SendType::Text,
            name: ENCRYPTED_STRING.parse().unwrap(),
            notes: None,
            file: None,
            text: None,
            data: None,
            key: ENCRYPTED_STRING.parse().unwrap(),
            max_access_count: None,
            access_count: 0,
            password: None,
            disabled: false,
            revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
            expiration_date: None,
            deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
            hide_email: false,
            emails: None,
            auth_type: crate::AuthType::None,
        }
    }

    fn make_test_client() -> (bitwarden_core::Client, Arc<MemoryRepository<Send>>) {
        let client = bitwarden_core::Client::new(None);
        let repository = Arc::new(MemoryRepository::<Send>::default());
        client
            .platform()
            .state()
            .register_client_managed(repository.clone());
        (client, repository)
    }

    #[tokio::test]
    async fn test_send_sync_handler_client_on_sync_persists_sends() {
        let (client, repository) = make_test_client();
        let handler = client.send_sync_handler();

        let id = uuid::Uuid::new_v4();
        handler.on_sync(vec![test_send(id)]).await.unwrap();

        let stored = repository.list().await.unwrap();
        assert_eq!(stored.len(), 1);
        assert!(repository.get(SendId::new(id)).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_send_sync_handler_client_on_sync_replaces_existing_sends() {
        let (client, repository) = make_test_client();
        let handler = client.send_sync_handler();

        let id1 = uuid::Uuid::new_v4();
        let id2 = uuid::Uuid::new_v4();
        handler
            .on_sync(vec![test_send(id1), test_send(id2)])
            .await
            .unwrap();
        assert_eq!(repository.list().await.unwrap().len(), 2);

        let id3 = uuid::Uuid::new_v4();
        handler.on_sync(vec![test_send(id3)]).await.unwrap();

        let stored = repository.list().await.unwrap();
        assert_eq!(stored.len(), 1);
        assert!(repository.get(SendId::new(id1)).await.unwrap().is_none());
        assert!(repository.get(SendId::new(id2)).await.unwrap().is_none());
        assert!(repository.get(SendId::new(id3)).await.unwrap().is_some());
    }
}
