use bitwarden_core::{Client, FromClient};

use crate::migration::{Migration, run_migrations};

/// Runs the encrypted migrations of the account.
#[bitwarden_ffi::wasm_object]
pub struct EncryptedMigratorClient {
    migrations: Vec<Migration>,
}

impl FromClient for EncryptedMigratorClient {
    fn from_client(client: &Client) -> Self {
        Self {
            migrations: Migration::all(client),
        }
    }
}

#[bitwarden_ffi::wasm_export]
impl EncryptedMigratorClient {
    /// Runs each migration once, in registration order. A failed migration does not stop the
    /// others.
    ///
    /// Two runs at the same time can send the same changes to the server, so the caller must not
    /// start a run before the previous run ends.
    pub async fn run_migrations(&self) {
        run_migrations(&self.migrations).await;
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

    /// The mock checks that the migration sent its request once.
    #[tokio::test]
    async fn test_run_migrations_runs_each_migration() {
        let owner = organization(OrganizationUserType::Owner);
        let owner_id = owner.details.id;
        let client = client(&[owner], &[owner_id], |mock| {
            expect_no_pending(mock, owner_id);
        })
        .await;

        client.encrypted_migrator().run_migrations().await;
    }
}
