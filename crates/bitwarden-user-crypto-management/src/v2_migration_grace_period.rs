//! Grace period gating for the v2 encrypted migrations master-password prompt.
//!
//! A user gets two weeks before the client asks for the master password. The window is anchored by
//! the state bridge value `v2_encrypted_migrations_grace_period_start`, which this module is the
//! only consumer of. The first query starts the clock.

use bitwarden_core::key_management::V2EncryptedMigrationsGracePeriodStart;
use bitwarden_error::bitwarden_error;
use chrono::{TimeDelta, Utc};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::UserCryptoManagementClient;

/// How long the prompt stays suppressed after the window opens.
const GRACE_PERIOD: TimeDelta = TimeDelta::weeks(2);

/// Errors returned by the v2 migration grace period check.
#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum V2MigrationGracePeriodError {
    /// The grace period starting timestamp lives in client-managed state, which needs a bridge.
    #[error("No state bridge registered, the v2 migration grace period is not supported")]
    StateBridgeNotRegistered,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
impl UserCryptoManagementClient {
    /// Returns whether the user is still inside the two-week v2 migration grace period.
    ///
    /// `true` means the master-password prompt must **not** be shown.
    ///
    /// The first call has a side effect: when no timestamp is stored, it writes
    /// the current timestamp and returns `true`. The window is therefore two
    /// weeks from the first call, not from login. A client that never calls
    /// this method never opens the window.
    ///
    /// The SDK never clears the timestamp. Clearing is the client's decision
    /// and resets the window. The timestamp is persisted so a user who logs out
    /// often cannot avoid the prompt indefinitely.
    ///
    /// Returns an error when no state bridge is registered.
    pub async fn within_v2_migration_grace_period(
        &self,
    ) -> Result<bool, V2MigrationGracePeriodError> {
        let state_bridge = self.client.km_state_bridge();
        if !state_bridge.is_bridge_registered() {
            return Err(V2MigrationGracePeriodError::StateBridgeNotRegistered);
        }

        match state_bridge
            .get_v2_encrypted_migrations_grace_period_start()
            .await
        {
            // The grace period's starting timestamp isn't set yet. The user is
            // inside the window by definition.
            None => {
                state_bridge
                    .set_v2_encrypted_migrations_grace_period_start(
                        &V2EncryptedMigrationsGracePeriodStart(Utc::now()),
                    )
                    .await;
                Ok(true)
            }
            Some(start) => Ok(Utc::now().signed_duration_since(start.0) < GRACE_PERIOD),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::{Client, key_management::state_bridge::test_support::InMemoryStateBridge};
    use chrono::DateTime;

    use super::*;
    use crate::UserCryptoManagementClientExt;

    /// Builds a client with an empty in-memory state bridge registered.
    fn client_with_bridge() -> Client {
        let client = Client::new(None);
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));
        client
    }

    /// Builds a client whose grace period anchor sits `offset` away from now. A negative offset is
    /// an anchor in the past.
    async fn client_with_anchor(offset: TimeDelta) -> Client {
        let client = client_with_bridge();
        client
            .km_state_bridge()
            .set_v2_encrypted_migrations_grace_period_start(&V2EncryptedMigrationsGracePeriodStart(
                Utc::now() + offset,
            ))
            .await;
        client
    }

    async fn stored_anchor(client: &Client) -> Option<DateTime<Utc>> {
        client
            .km_state_bridge()
            .get_v2_encrypted_migrations_grace_period_start()
            .await
            .map(|start| start.0)
    }

    #[tokio::test]
    async fn test_unset_anchor_starts_the_window_and_reports_within() {
        let client = client_with_bridge();

        assert!(
            client
                .user_crypto_management()
                .within_v2_migration_grace_period()
                .await
                .unwrap()
        );

        let anchor = stored_anchor(&client).await.expect("the window was armed");
        assert!(Utc::now().signed_duration_since(anchor) < TimeDelta::seconds(5));
    }

    #[tokio::test]
    async fn test_second_call_does_not_move_the_anchor() {
        let client = client_with_bridge();
        let user_crypto_management = client.user_crypto_management();

        assert!(
            user_crypto_management
                .within_v2_migration_grace_period()
                .await
                .unwrap()
        );
        let armed = stored_anchor(&client).await.expect("the window was armed");

        assert!(
            user_crypto_management
                .within_v2_migration_grace_period()
                .await
                .unwrap()
        );
        assert_eq!(stored_anchor(&client).await, Some(armed));
    }

    #[tokio::test]
    async fn test_one_week_old_anchor_is_within() {
        let client = client_with_anchor(-TimeDelta::weeks(1)).await;

        assert!(
            client
                .user_crypto_management()
                .within_v2_migration_grace_period()
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_three_week_old_anchor_is_outside() {
        let client = client_with_anchor(-TimeDelta::weeks(3)).await;

        assert!(
            !client
                .user_crypto_management()
                .within_v2_migration_grace_period()
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_exactly_two_weeks_is_outside() {
        // The anchor is written a moment before it is read, so the elapsed time is just past the
        // grace period and the strict comparison reports the user as outside it.
        let client = client_with_anchor(-GRACE_PERIOD).await;

        assert!(
            !client
                .user_crypto_management()
                .within_v2_migration_grace_period()
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_future_anchor_is_within_and_untouched() {
        let client = client_with_anchor(TimeDelta::weeks(1)).await;
        let anchor = stored_anchor(&client).await;

        assert!(
            client
                .user_crypto_management()
                .within_v2_migration_grace_period()
                .await
                .unwrap()
        );
        assert_eq!(stored_anchor(&client).await, anchor);
    }

    #[tokio::test]
    async fn test_without_a_state_bridge_errors() {
        let client = Client::new(None);

        assert!(matches!(
            client
                .user_crypto_management()
                .within_v2_migration_grace_period()
                .await,
            Err(V2MigrationGracePeriodError::StateBridgeNotRegistered)
        ));
    }
}
