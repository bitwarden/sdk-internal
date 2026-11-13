//! The encrypted migrations and the order in which they run.

pub(crate) mod account_recovery_v2_upgrade;

use bitwarden_core::{Client, FromClient};

use self::account_recovery_v2_upgrade::AccountRecoveryV2UpgradeMigration;
use crate::runner::DynEncryptedMigration;

/// Every migration, in the order they run.
pub(crate) fn all(client: &Client) -> Vec<Box<dyn DynEncryptedMigration>> {
    vec![Box::new(AccountRecoveryV2UpgradeMigration::from_client(
        client,
    ))]
}
