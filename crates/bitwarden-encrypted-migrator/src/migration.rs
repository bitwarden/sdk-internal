//! The interface of an encrypted migration.
//!
//! To add a migration, add its module in `migrations/` with a type that implements
//! [`EncryptedMigration`], and add the migration to [`all`](crate::migrations::all) in the
//! position where it must run.

use bitwarden_sensitive_value::MasterPassword;
use bitwarden_threading::MaybeSend;

/// An encrypted migration of the account.
///
/// Another device can run the same migration at the same time. Design the migration so that the
/// server rejects the second run, and so that a rejected or failed run leaves the account usable.
pub(crate) trait EncryptedMigration: Send + Sync {
    /// The name of the migration in the logs.
    const NAME: &'static str;

    /// Checks the current state of the account.
    fn needs_migration(&self) -> MigrationNeed;

    /// Runs the migration. A migration logs its own failures and runs again after the next unlock
    /// or sync.
    ///
    /// Gets the master password when [`EncryptedMigration::needs_migration`] returns
    /// [`MigrationNeed::NeedsMasterPassword`].
    fn run(&self, master_password: Option<&MasterPassword>)
    -> impl Future<Output = ()> + MaybeSend;
}

/// Whether the account needs a migration, and what the migration needs to run.
#[cfg_attr(not(test), expect(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MigrationNeed {
    /// The data of the account is already in the current format.
    NotNeeded,
    /// The account needs the migration. The migration needs only the unlocked account.
    Needed,
    /// The account needs the migration. The migration needs the unlocked account and the master
    /// password.
    NeedsMasterPassword,
}
