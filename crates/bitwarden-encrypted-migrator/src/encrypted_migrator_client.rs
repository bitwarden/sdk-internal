use bitwarden_core::{
    Client, FromClient,
    key_management::{UnlockHandler, crypto::InitUserCryptoMethod},
};

use crate::scheduler;

/// Schedules the background encrypted migrations of the account.
pub struct EncryptedMigratorClient {
    // The whole client, because each run creates the migrations again from the client.
    client: Client,
}

impl FromClient for EncryptedMigratorClient {
    fn from_client(client: &Client) -> Self {
        Self {
            client: client.clone(),
        }
    }
}

impl EncryptedMigratorClient {
    /// Schedules the background migrations of the client's user after a short delay, replacing a
    /// scheduled run that has not started.
    ///
    /// Does not schedule a run while a run is in progress, for example when the server pushes a
    /// sync to the client before the run ends.
    pub fn trigger_background_migrations(&self) {
        scheduler::trigger(&self.client);
    }
}

/// Schedules the background migrations after an explicit unlock.
///
/// Only the SDK client that the user unlocks schedules the run. A client that is initialized from
/// client-managed state, for example a re-created client or the popup client next to the background
/// client, and `reinit_user_crypto` do not schedule a run.
pub struct EncryptedMigratorUnlockHandler;

impl UnlockHandler for EncryptedMigratorUnlockHandler {
    fn on_unlock(&self, client: &Client, method: Option<&InitUserCryptoMethod>) {
        match method {
            #[cfg(feature = "wasm")]
            Some(InitUserCryptoMethod::ClientManagedState {}) => {}
            Some(_) => client.encrypted_migrator().trigger_background_migrations(),
            None => {}
        }
    }
}

/// Extension trait that exposes [`EncryptedMigratorClient`] on [`Client`].
pub trait EncryptedMigratorClientExt {
    /// Returns an [`EncryptedMigratorClient`].
    fn encrypted_migrator(&self) -> EncryptedMigratorClient;
}

impl EncryptedMigratorClientExt for Client {
    fn encrypted_migrator(&self) -> EncryptedMigratorClient {
        EncryptedMigratorClient::from_client(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::tests::{is_scheduled, unlocked_client};

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_on_unlock_with_an_unlock_method_schedules_a_run() {
        let (client, user_id) = unlocked_client().await;

        EncryptedMigratorUnlockHandler.on_unlock(
            &client,
            Some(&InitUserCryptoMethod::DecryptedKey {
                decrypted_user_key: String::new(),
            }),
        );

        assert!(is_scheduled(user_id));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_on_unlock_from_reinit_user_crypto_schedules_nothing() {
        let (client, user_id) = unlocked_client().await;

        EncryptedMigratorUnlockHandler.on_unlock(&client, None);

        assert!(!is_scheduled(user_id));
    }

    #[cfg(feature = "wasm")]
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_on_unlock_from_client_managed_state_schedules_nothing() {
        let (client, user_id) = unlocked_client().await;

        EncryptedMigratorUnlockHandler
            .on_unlock(&client, Some(&InitUserCryptoMethod::ClientManagedState {}));

        assert!(!is_scheduled(user_id));
    }
}
