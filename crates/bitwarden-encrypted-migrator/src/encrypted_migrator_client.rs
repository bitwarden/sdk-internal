use std::sync::Arc;

use bitwarden_core::{Client, FromClient};
use tracing::{Instrument, info_span};

use crate::{
    migration::{Migration, MigrationStage},
    migrations::account_recovery_v2_upgrade::AccountRecoveryV2UpgradeMigration,
};

/// Runs the encrypted migrations of the account.
#[bitwarden_ffi::wasm_object]
pub struct EncryptedMigratorClient {
    migrations: Arc<Vec<Migration>>,
}

impl FromClient for EncryptedMigratorClient {
    fn from_client(client: &Client) -> Self {
        Self {
            migrations: Arc::new(vec![Migration::AccountRecoveryV2Upgrade(
                AccountRecoveryV2UpgradeMigration::from_client(client),
            )]),
        }
    }
}

#[bitwarden_ffi::wasm_export]
impl EncryptedMigratorClient {
    /// Starts the background migrations and returns without waiting for them.
    ///
    /// A failed migration does not stop the others, and runs again on the next call.
    pub fn run_background_migrations(&self) {
        let migrations = Arc::clone(&self.migrations);
        bitwarden_threading::spawn(async move {
            run_migrations(&migrations, MigrationStage::Background).await;
        });
    }
}

/// Runs the migrations of `stage` one after another, in registration order.
async fn run_migrations(migrations: &[Migration], stage: MigrationStage) {
    for migration in migrations.iter().filter(|m| m.stage() == stage) {
        migration
            .run()
            .instrument(info_span!("encrypted_migration", name = migration.name()))
            .await;
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
    use bitwarden_organizations::OrganizationUserType;

    use super::*;
    use crate::migrations::account_recovery_v2_upgrade::tests::{
        client, expect_no_pending, organization,
    };

    #[tokio::test]
    async fn test_background_run_runs_background_migrations() {
        let owner = organization(OrganizationUserType::Owner);
        let owner_id = owner.details.id;
        let client = client(&[owner], &[owner_id], |mock| {
            expect_no_pending(mock, owner_id);
        })
        .await;

        run_migrations(
            &client.encrypted_migrator().migrations,
            MigrationStage::Background,
        )
        .await;
    }

    /// The API mock fails any request, so a foreground run that ran a background migration fails.
    #[tokio::test]
    async fn test_foreground_run_skips_background_migrations() {
        let owner = organization(OrganizationUserType::Owner);
        let owner_id = owner.details.id;
        let client = client(&[owner], &[owner_id], |_| {}).await;

        run_migrations(
            &client.encrypted_migrator().migrations,
            MigrationStage::Foreground,
        )
        .await;
    }
}
