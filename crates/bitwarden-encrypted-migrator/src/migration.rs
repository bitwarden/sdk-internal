//! The encrypted migrations and the order in which they run.
//!
//! To add a migration, add its module in `migrations/`, add a variant to [`Migration`], and add the
//! migration to [`Migration::all`] in the position where it must run.

use bitwarden_core::{Client, FromClient};
use tracing::{Instrument, info_span};

use crate::migrations::account_recovery_v2_upgrade::AccountRecoveryV2UpgradeMigration;

/// An encrypted migration. A migration does not change data that is already in the current
/// format, so it can run again.
// An enum rather than a trait object, because API futures are not `Send` on wasm32.
pub(crate) enum Migration {
    AccountRecoveryV2Upgrade(AccountRecoveryV2UpgradeMigration),
}

impl Migration {
    /// Every migration, in the order they run.
    pub(crate) fn all(client: &Client) -> Vec<Migration> {
        vec![Migration::AccountRecoveryV2Upgrade(
            AccountRecoveryV2UpgradeMigration::from_client(client),
        )]
    }

    pub(crate) fn name(&self) -> &'static str {
        match self {
            Migration::AccountRecoveryV2Upgrade(_) => "account_recovery_v2_upgrade",
        }
    }

    /// Runs the migration. A migration logs its own failures and is retried on the next run.
    pub(crate) async fn run(&self) {
        match self {
            Migration::AccountRecoveryV2Upgrade(migration) => migration.run().await,
        }
    }
}

/// Runs the migrations one after another, in registration order.
pub(crate) async fn run_migrations(migrations: &[Migration]) {
    for migration in migrations {
        migration
            .run()
            .instrument(info_span!("encrypted_migration", name = migration.name()))
            .await;
    }
}
