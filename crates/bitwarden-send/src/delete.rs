use bitwarden_api_api::ResponseContent;
use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use bitwarden_state::{
    Setting, register_setting_key,
    repository::{Repository, RepositoryError},
};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{Send, SendId, send_client::SendClient};

// Durable queue of Sends whose server-side delete failed, retried later to avoid orphaned records.
register_setting_key!(const PENDING_SEND_DELETIONS: Vec<SendId> = "pendingSendDeletions");

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum DeleteSendError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    State(#[from] bitwarden_state::SettingsError),
}

async fn delete_send<R: Repository<Send> + ?Sized>(
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    pending_deletions: &Setting<Vec<SendId>>,
    send_id: SendId,
) -> Result<(), DeleteSendError> {
    if let Err(e) = api_client.sends_api().delete(&send_id.to_string()).await {
        // Often an offline failure; queue for durable retry so the Send isn't orphaned in the list.
        queue_pending_deletion(pending_deletions, send_id).await;
        return Err(e.into());
    }

    repository.remove(send_id).await?;

    Ok(())
}

/// Add `send_id` to the pending-deletion queue if not already present. Setting errors are
/// swallowed so the caller still receives the original delete error unchanged.
async fn queue_pending_deletion(pending_deletions: &Setting<Vec<SendId>>, send_id: SendId) {
    let mut queue = match pending_deletions.get().await {
        Ok(queue) => queue.unwrap_or_default(),
        Err(e) => {
            tracing::warn!("Failed to read pending send deletions: {e}");
            return;
        }
    };

    if queue.contains(&send_id) {
        return;
    }

    queue.push(send_id);
    if let Err(e) = pending_deletions.update(queue).await {
        tracing::warn!("Failed to queue send for pending deletion: {e}");
    }
}

async fn retry_pending_deletions<R: Repository<Send> + ?Sized>(
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    pending_deletions: &Setting<Vec<SendId>>,
) -> Result<(), DeleteSendError> {
    let queue = pending_deletions.get().await?.unwrap_or_default();
    if queue.is_empty() {
        return Ok(());
    }

    let mut resolved = Vec::new();
    for send_id in queue {
        match api_client.sends_api().delete(&send_id.to_string()).await {
            // A 404 means it's already gone server-side, so treat it the same as a success.
            Ok(())
            | Err(ApiError::Response(ResponseContent {
                status: reqwest::StatusCode::NOT_FOUND,
                ..
            })) => {
                // Repo may already be clean; ignore removal errors.
                let _ = repository.remove(send_id).await;
                resolved.push(send_id);
            }
            Err(_) => {}
        }
    }

    if resolved.is_empty() {
        return Ok(());
    }

    // Re-read before writing so a concurrent queue_pending_deletion isn't clobbered.
    let mut current = pending_deletions.get().await?.unwrap_or_default();
    current.retain(|id| !resolved.contains(id));
    pending_deletions.update(current).await?;

    Ok(())
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl SendClient {
    /// Delete a [Send] from the server and remove it from local state.
    pub async fn delete(&self, send_id: SendId) -> Result<(), DeleteSendError> {
        let config = self.client.internal.get_api_configurations();
        let repository = self.get_repository()?;
        let pending_deletions = self
            .client
            .platform()
            .state()
            .setting(PENDING_SEND_DELETIONS)?;

        delete_send(
            &config.api_client,
            repository.as_ref(),
            &pending_deletions,
            send_id,
        )
        .await
    }

    /// Retry any [Send] deletions that previously failed (e.g. while offline), removing each from
    /// the pending queue once the server confirms it is gone.
    pub async fn retry_pending_deletions(&self) -> Result<(), DeleteSendError> {
        let config = self.client.internal.get_api_configurations();
        let repository = self.get_repository()?;
        let pending_deletions = self
            .client
            .platform()
            .state()
            .setting(PENDING_SEND_DELETIONS)?;

        retry_pending_deletions(&config.api_client, repository.as_ref(), &pending_deletions).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::apis::ApiClient;
    use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
    use bitwarden_crypto::{KeyStore, SymmetricKeyAlgorithm};
    use bitwarden_state::SettingItem;
    use bitwarden_test::MemoryRepository;
    use uuid::uuid;

    use super::*;
    use crate::{AuthType, Send, SendId, SendTextView, SendType, SendView};

    fn make_pending_setting() -> Setting<Vec<SendId>> {
        let repository: Arc<dyn Repository<SettingItem>> =
            Arc::new(MemoryRepository::<SettingItem>::default());
        Setting::new(repository, PENDING_SEND_DELETIONS)
    }

    async fn make_store_with_send(
        send_id: uuid::Uuid,
    ) -> (KeyStore<KeySlotIds>, MemoryRepository<Send>) {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeySlotId::User)
                .unwrap();
        }

        let repository = MemoryRepository::<Send>::default();
        let send_view = SendView {
            id: None,
            access_id: None,
            name: "Test Send".to_string(),
            notes: None,
            key: None,
            new_password: None,
            has_password: false,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("Secret text".to_string()),
                hidden: false,
            }),
            data: None,
            max_access_count: None,
            access_count: 0,
            disabled: false,
            hide_email: false,
            revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
            deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
            expiration_date: None,
            emails: Vec::new(),
            auth_type: AuthType::None,
        };
        let mut send = store.encrypt(send_view).unwrap();
        send.id = Some(SendId::new(send_id));
        repository.set(SendId::new(send_id), send).await.unwrap();

        (store, repository)
    }

    #[tokio::test]
    async fn test_delete_send() {
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let (_store, repository) = make_store_with_send(send_id).await;
        let pending = make_pending_setting();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api
                .expect_delete()
                .returning(move |_id| Ok(()))
                .once();
        });

        let result = delete_send(&api_client, &repository, &pending, SendId::new(send_id)).await;

        assert!(result.is_ok());
        assert!(
            repository
                .get(SendId::new(send_id))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_delete_send_http_error() {
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let (_store, repository) = make_store_with_send(send_id).await;
        let pending = make_pending_setting();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api
                .expect_delete()
                .returning(move |_id| {
                    Err(bitwarden_api_api::ApiError::Io(std::io::Error::other(
                        "Simulated error",
                    )))
                })
                .once();
        });

        let result = delete_send(&api_client, &repository, &pending, SendId::new(send_id)).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DeleteSendError::Api(_)));
        // Send should still be in the repository since API call failed
        assert!(
            repository
                .get(SendId::new(send_id))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_delete_send_failure_queues_pending_deletion() {
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let (_store, repository) = make_store_with_send(send_id).await;
        let pending = make_pending_setting();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api.expect_delete().returning(move |_id| {
                Err(bitwarden_api_api::ApiError::Io(std::io::Error::other(
                    "Simulated error",
                )))
            });
        });

        let result = delete_send(&api_client, &repository, &pending, SendId::new(send_id)).await;
        assert!(result.is_err());

        let queue = pending.get().await.unwrap().unwrap_or_default();
        assert_eq!(queue, vec![SendId::new(send_id)]);
    }

    #[tokio::test]
    async fn test_delete_send_failure_does_not_duplicate_queue_entry() {
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let (_store, repository) = make_store_with_send(send_id).await;
        let pending = make_pending_setting();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api.expect_delete().returning(move |_id| {
                Err(bitwarden_api_api::ApiError::Io(std::io::Error::other(
                    "Simulated error",
                )))
            });
        });

        assert!(
            delete_send(&api_client, &repository, &pending, SendId::new(send_id))
                .await
                .is_err()
        );
        assert!(
            delete_send(&api_client, &repository, &pending, SendId::new(send_id))
                .await
                .is_err()
        );

        let queue = pending.get().await.unwrap().unwrap_or_default();
        assert_eq!(queue, vec![SendId::new(send_id)]);
    }

    #[tokio::test]
    async fn test_retry_pending_deletions_success_removes_from_queue_and_repository() {
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let (_store, repository) = make_store_with_send(send_id).await;
        let pending = make_pending_setting();
        pending.update(vec![SendId::new(send_id)]).await.unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api
                .expect_delete()
                .returning(move |_id| Ok(()))
                .once();
        });

        retry_pending_deletions(&api_client, &repository, &pending)
            .await
            .unwrap();

        let queue = pending.get().await.unwrap().unwrap_or_default();
        assert!(queue.is_empty());
        assert!(
            repository
                .get(SendId::new(send_id))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_retry_pending_deletions_not_found_is_resolved() {
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let (_store, repository) = make_store_with_send(send_id).await;
        let pending = make_pending_setting();
        pending.update(vec![SendId::new(send_id)]).await.unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api
                .expect_delete()
                .returning(move |_id| {
                    Err(bitwarden_api_api::ApiError::Response(ResponseContent {
                        status: reqwest::StatusCode::NOT_FOUND,
                        message: "not found".to_string(),
                    }))
                })
                .once();
        });

        retry_pending_deletions(&api_client, &repository, &pending)
            .await
            .unwrap();

        let queue = pending.get().await.unwrap().unwrap_or_default();
        assert!(queue.is_empty());
        assert!(
            repository
                .get(SendId::new(send_id))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_retry_pending_deletions_other_error_stays_queued() {
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let (_store, repository) = make_store_with_send(send_id).await;
        let pending = make_pending_setting();
        pending.update(vec![SendId::new(send_id)]).await.unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api
                .expect_delete()
                .returning(move |_id| {
                    Err(bitwarden_api_api::ApiError::Io(std::io::Error::other(
                        "Simulated error",
                    )))
                })
                .once();
        });

        retry_pending_deletions(&api_client, &repository, &pending)
            .await
            .unwrap();

        let queue = pending.get().await.unwrap().unwrap_or_default();
        assert_eq!(queue, vec![SendId::new(send_id)]);
        // Still present server-side (from the client's view), so it must remain locally too.
        assert!(
            repository
                .get(SendId::new(send_id))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_retry_pending_deletions_mixed_batch() {
        let resolved_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let failing_id = uuid!("3b8e0f2a-1c4d-4e6f-9a7b-2d5c8e1f0a3b");
        let (store, repository) = make_store_with_send(resolved_id).await;
        // Add a second send sharing the same store so both live in one repository.
        let mut send = store
            .encrypt(SendView {
                id: None,
                access_id: None,
                name: "Test Send".to_string(),
                notes: None,
                key: None,
                new_password: None,
                has_password: false,
                r#type: SendType::Text,
                file: None,
                text: Some(SendTextView {
                    text: Some("Secret text".to_string()),
                    hidden: false,
                }),
                data: None,
                max_access_count: None,
                access_count: 0,
                disabled: false,
                hide_email: false,
                revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
                deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
                expiration_date: None,
                emails: Vec::new(),
                auth_type: AuthType::None,
            })
            .unwrap();
        send.id = Some(SendId::new(failing_id));
        repository.set(SendId::new(failing_id), send).await.unwrap();

        let pending = make_pending_setting();
        pending
            .update(vec![SendId::new(resolved_id), SendId::new(failing_id)])
            .await
            .unwrap();

        let resolved_id_str = resolved_id.to_string();
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api.expect_delete().returning(move |id| {
                if id == resolved_id_str {
                    Ok(())
                } else {
                    Err(bitwarden_api_api::ApiError::Io(std::io::Error::other(
                        "Simulated error",
                    )))
                }
            });
        });

        retry_pending_deletions(&api_client, &repository, &pending)
            .await
            .unwrap();

        let queue = pending.get().await.unwrap().unwrap_or_default();
        assert_eq!(queue, vec![SendId::new(failing_id)]);
        assert!(
            repository
                .get(SendId::new(resolved_id))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repository
                .get(SendId::new(failing_id))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_retry_pending_deletions_empty_queue_is_noop() {
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let (_store, repository) = make_store_with_send(send_id).await;
        let pending = make_pending_setting();

        // No delete calls expected for an empty queue.
        let api_client = ApiClient::new_mocked(|_mock| {});

        retry_pending_deletions(&api_client, &repository, &pending)
            .await
            .unwrap();
    }
}
