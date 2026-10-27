use crate::migrations::account_recovery_v2_upgrade::AccountRecoveryV2UpgradeMigration;

/// When a migration runs relative to unlock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MigrationStage {
    /// The migration runs as part of login and unlock, and must finish before the vault is usable.
    #[allow(dead_code)] // No migration runs in the foreground yet.
    Foreground,
    /// The migration runs on a schedule while the account is unlocked, without blocking the user.
    Background,
}

/// A migration the migrator runs.
///
/// An enum rather than a trait object, because API futures are not `Send` on wasm32.
pub(crate) enum Migration {
    AccountRecoveryV2Upgrade(AccountRecoveryV2UpgradeMigration),
}

impl Migration {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Migration::AccountRecoveryV2Upgrade(_) => "account_recovery_v2_upgrade",
        }
    }

    pub(crate) fn stage(&self) -> MigrationStage {
        match self {
            Migration::AccountRecoveryV2Upgrade(_) => MigrationStage::Background,
        }
    }

    /// Runs the migration. A migration logs its own failures and is retried on the next run.
    pub(crate) async fn run(&self) {
        match self {
            Migration::AccountRecoveryV2Upgrade(migration) => migration.run().await,
        }
    }
}
