//! Runs a list of encrypted migrations of different types.

use bitwarden_threading::BoxFuture;
use tracing::{Instrument, info, info_span};
use zeroize::Zeroizing;

use crate::migration::{EncryptedMigration, MigrationNeed};

/// An [`EncryptedMigration`] behind a trait object, so that one list can hold migrations of
/// different types.
pub(crate) trait DynEncryptedMigration: Send + Sync {
    fn name(&self) -> &'static str;

    fn needs_migration(&self) -> MigrationNeed;

    fn run<'a>(&'a self, master_password: Option<&'a Zeroizing<String>>) -> BoxFuture<'a, ()>;
}

impl<M: EncryptedMigration> DynEncryptedMigration for M {
    fn name(&self) -> &'static str {
        M::NAME
    }

    fn needs_migration(&self) -> MigrationNeed {
        EncryptedMigration::needs_migration(self)
    }

    fn run<'a>(&'a self, master_password: Option<&'a Zeroizing<String>>) -> BoxFuture<'a, ()> {
        Box::pin(EncryptedMigration::run(self, master_password))
    }
}

/// Runs the migrations that the account needs, one after another, in registration order. Checks
/// each migration right before it runs, so that it sees the changes of the migrations before it.
/// Without `master_password`, skips the migrations that need it.
pub(crate) async fn run_migrations(
    migrations: &[Box<dyn DynEncryptedMigration>],
    master_password: Option<&Zeroizing<String>>,
) {
    for migration in migrations {
        async {
            match migration.needs_migration() {
                MigrationNeed::NotNeeded => {}
                MigrationNeed::NeedsMasterPassword if master_password.is_none() => {
                    info!("Skipped, because the migration needs the master password");
                }
                MigrationNeed::Needed | MigrationNeed::NeedsMasterPassword => {
                    migration.run(master_password).await
                }
            }
        }
        .instrument(info_span!("encrypted_migration", name = migration.name()))
        .await;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    pub(crate) type FakeRun = Arc<dyn Fn(Option<&Zeroizing<String>>) + Send + Sync>;

    pub(crate) struct FakeMigration {
        pub(crate) need: MigrationNeed,
        pub(crate) run: FakeRun,
    }

    impl EncryptedMigration for FakeMigration {
        const NAME: &'static str = "fake";

        fn needs_migration(&self) -> MigrationNeed {
            self.need
        }

        async fn run(&self, master_password: Option<&Zeroizing<String>>) {
            (self.run)(master_password)
        }
    }

    type RunLog = Arc<Mutex<Vec<(&'static str, Option<String>)>>>;

    fn recording(
        name: &'static str,
        need: MigrationNeed,
        log: &RunLog,
    ) -> Box<dyn DynEncryptedMigration> {
        let log = Arc::clone(log);
        Box::new(FakeMigration {
            need,
            run: Arc::new(move |master_password| {
                log.lock()
                    .expect("Mutex is not poisoned")
                    .push((name, master_password.map(|p| p.to_string())))
            }),
        })
    }

    fn runs(log: &RunLog) -> Vec<(&'static str, Option<String>)> {
        log.lock().expect("Mutex is not poisoned").clone()
    }

    #[tokio::test]
    async fn test_run_migrations_runs_each_migration_once_in_registration_order() {
        let log = RunLog::default();
        let migrations = [
            recording("first", MigrationNeed::Needed, &log),
            recording("second", MigrationNeed::Needed, &log),
        ];

        run_migrations(&migrations, None).await;

        assert_eq!(runs(&log), [("first", None), ("second", None)]);
    }

    #[tokio::test]
    async fn test_run_migrations_skips_a_migration_that_is_not_needed() {
        let log = RunLog::default();
        let migrations = [
            recording("not_needed", MigrationNeed::NotNeeded, &log),
            recording("needed", MigrationNeed::Needed, &log),
        ];

        run_migrations(&migrations, None).await;

        assert_eq!(runs(&log), [("needed", None)]);
    }

    #[tokio::test]
    async fn test_run_migrations_without_the_master_password_skips_a_migration_that_needs_it() {
        let log = RunLog::default();
        let migrations = [
            recording("master_password", MigrationNeed::NeedsMasterPassword, &log),
            recording("needed", MigrationNeed::Needed, &log),
        ];

        run_migrations(&migrations, None).await;

        assert_eq!(runs(&log), [("needed", None)]);
    }

    #[tokio::test]
    async fn test_run_migrations_with_the_master_password_passes_it_to_each_migration() {
        let log = RunLog::default();
        let migrations = [
            recording("master_password", MigrationNeed::NeedsMasterPassword, &log),
            recording("needed", MigrationNeed::Needed, &log),
        ];
        let master_password = Zeroizing::new("master password".to_string());

        run_migrations(&migrations, Some(&master_password)).await;

        assert_eq!(
            runs(&log),
            [
                ("master_password", Some("master password".to_string())),
                ("needed", Some("master password".to_string())),
            ]
        );
    }
}
