use bitwarden_core::key_management::KeyIds;
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;
use uuid::Uuid;

use crate::{Send, SendView, error::ItemNotFoundError};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum GetSendError {
    #[error(transparent)]
    ItemNotFound(#[from] ItemNotFoundError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub(super) async fn get_send(
    store: &KeyStore<KeyIds>,
    repository: &dyn Repository<Send>,
    id: Uuid,
) -> Result<SendView, GetSendError> {
    let send = repository
        .get(id.to_string())
        .await?
        .ok_or(ItemNotFoundError)?;

    Ok(store.decrypt(&send)?)
}

pub(super) async fn list_sends(
    store: &KeyStore<KeyIds>,
    repository: &dyn Repository<Send>,
) -> Result<Vec<SendView>, GetSendError> {
    let sends = repository.list().await?;
    let views = store.decrypt_list(&sends)?;
    Ok(views)
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::SymmetricKeyId;
    use bitwarden_crypto::SymmetricKeyAlgorithm;
    use bitwarden_test::MemoryRepository;
    use uuid::uuid;

    use super::*;
    use crate::{AuthType, SendTextView, SendType, SendView};

    #[tokio::test]
    async fn test_get_send() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeyId::User)
                .unwrap();
        }

        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");

        // Create and store a send
        let repository = MemoryRepository::<Send>::default();
        let send_view = SendView {
            id: None,
            access_id: None,
            name: "Test Send".to_string(),
            notes: Some("Test notes".to_string()),
            key: None,
            new_password: None,
            has_password: false,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("Secret text".to_string()),
                hidden: false,
            }),
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
        send.id = Some(send_id);
        repository.set(send_id.to_string(), send).await.unwrap();

        // Test getting the send
        let result = get_send(&store, &repository, send_id).await.unwrap();

        assert_eq!(result.id, Some(send_id));
        assert_eq!(result.name, "Test Send");
        assert_eq!(result.notes, Some("Test notes".to_string()));
        assert_eq!(
            result.text,
            Some(SendTextView {
                text: Some("Secret text".to_string()),
                hidden: false,
            })
        );
    }

    #[tokio::test]
    async fn test_get_send_not_found() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeyId::User)
                .unwrap();
        }

        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let repository = MemoryRepository::<Send>::default();

        // Try to get a send that doesn't exist
        let result = get_send(&store, &repository, send_id).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GetSendError::ItemNotFound(_)));
    }

    #[tokio::test]
    async fn test_list_sends() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeyId::User)
                .unwrap();
        }

        let repository = MemoryRepository::<Send>::default();

        // Create and store multiple sends
        let send_id_1 = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let send_view_1 = SendView {
            id: None,
            access_id: None,
            name: "Send 1".to_string(),
            notes: None,
            key: None,
            new_password: None,
            has_password: false,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("Text 1".to_string()),
                hidden: false,
            }),
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
        let mut send_1 = store.encrypt(send_view_1).unwrap();
        send_1.id = Some(send_id_1);
        repository.set(send_id_1.to_string(), send_1).await.unwrap();

        let send_id_2 = uuid!("36afb22c-9c95-4db5-8bac-c21cb204a3f2");
        let send_view_2 = SendView {
            id: None,
            access_id: None,
            name: "Send 2".to_string(),
            notes: None,
            key: None,
            new_password: None,
            has_password: false,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("Text 2".to_string()),
                hidden: false,
            }),
            max_access_count: None,
            access_count: 0,
            disabled: false,
            hide_email: false,
            revision_date: "2025-01-02T00:00:00Z".parse().unwrap(),
            deletion_date: "2025-01-11T00:00:00Z".parse().unwrap(),
            expiration_date: None,
            emails: Vec::new(),
            auth_type: AuthType::None,
        };
        let mut send_2 = store.encrypt(send_view_2).unwrap();
        send_2.id = Some(send_id_2);
        repository.set(send_id_2.to_string(), send_2).await.unwrap();

        // Test listing all sends
        let result = list_sends(&store, &repository).await.unwrap();

        assert_eq!(result.len(), 2);

        // Find sends by name (order may vary)
        let send1 = result.iter().find(|s| s.name == "Send 1").unwrap();
        let send2 = result.iter().find(|s| s.name == "Send 2").unwrap();

        assert_eq!(send1.id, Some(send_id_1));
        assert_eq!(send2.id, Some(send_id_2));
    }

    #[tokio::test]
    async fn test_list_sends_empty() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeyId::User)
                .unwrap();
        }

        let repository = MemoryRepository::<Send>::default();

        // Test listing when repository is empty
        let result = list_sends(&store, &repository).await.unwrap();

        assert_eq!(result.len(), 0);
    }
}

