//! Schedules the background migrations of each user.

use std::{
    sync::{Arc, LazyLock, Weak},
    time::Duration,
};

use bitwarden_core::{
    Client, UserId, client::internal::InternalClient, key_management::SymmetricKeySlotId,
};
use bitwarden_threading::cancellation_token::CancellationToken;
use tokio::sync::oneshot;

use crate::{
    migrations,
    runner::{DynEncryptedMigration, run_migrations},
    user_run_states::UserRunStates,
};

/// Gives the data of the unlock or the sync time to reach state before the run.
const TRIGGER_DELAY: Duration = Duration::from_secs(5);

/// Global to the process, not per [`Client`], because the TypeScript clients replace the SDK client
/// each time the account's keys change in their state.
static SCHEDULER: LazyLock<Arc<Scheduler>> =
    LazyLock::new(|| Arc::new(Scheduler::new(migrations::all)));

/// Schedules the background migrations of the client's user on the process-wide scheduler.
pub(crate) fn trigger(client: &Client) {
    SCHEDULER.trigger(client);
}

type MakeMigrations = dyn Fn(&Client) -> Vec<Box<dyn DynEncryptedMigration>> + Send + Sync;

struct Scheduler {
    user_run_states: UserRunStates,
    make_migrations: Box<MakeMigrations>,
}

impl Scheduler {
    fn new(
        make_migrations: impl Fn(&Client) -> Vec<Box<dyn DynEncryptedMigration>> + Send + Sync + 'static,
    ) -> Self {
        Self {
            user_run_states: UserRunStates::default(),
            make_migrations: Box::new(make_migrations),
        }
    }

    fn trigger(self: &Arc<Self>, client: &Client) {
        let Some(user_id) = client.internal.get_user_id() else {
            return;
        };
        let client = Arc::downgrade(&client.internal);
        if let Some(token) = self.user_run_states.try_schedule(user_id, &client) {
            self.spawn_delayed_run(client, user_id, token);
        }
    }

    /// Spawns a task that runs the migrations after [`TRIGGER_DELAY`]. After a trigger during the
    /// run, spawns the follow-up run, because a sync during the run can bring data that the run
    /// did not see.
    ///
    /// The task holds only a weak reference while it waits, so it does not keep a dropped client
    /// and its keys in memory.
    fn spawn_delayed_run(
        self: &Arc<Self>,
        client: Weak<InternalClient>,
        user_id: UserId,
        token: CancellationToken,
    ) {
        let scheduler = Arc::clone(self);
        bitwarden_threading::spawn(async move {
            if !wait_unless_replaced(&token, TRIGGER_DELAY).await {
                return;
            }
            let Some(client) = upgrade_if_unlocked(&client).await else {
                // The next unlock or sync schedules a new run.
                scheduler.user_run_states.remove(user_id, &token);
                return;
            };
            // At this point, a newer trigger might have replaced this schedule.
            if !scheduler
                .user_run_states
                .try_mark_run_in_progress(user_id, &token)
            {
                return;
            }
            scheduler.run_background_migrations(&client).await;
            if let Some((follow_up, client)) = scheduler.user_run_states.finish_run(user_id) {
                scheduler.spawn_delayed_run(client, user_id, follow_up);
            }
        });
    }

    /// Runs the migrations in a separate task and returns when the task ends, also when a
    /// migration panics.
    async fn run_background_migrations(&self, client: &Client) {
        let (finished_sender, finished_receiver) = oneshot::channel::<()>();
        let migrations = (self.make_migrations)(client);
        bitwarden_threading::spawn(async move {
            let _finished_sender = finished_sender;
            run_migrations(&migrations, None).await;
        });
        // The sender never sends, so the receiver resolves with an error once the task drops it.
        let _ = finished_receiver.await;
    }
}

/// Waits for `delay`. Returns `false` if a newer trigger cancels `token` first.
async fn wait_unless_replaced(token: &CancellationToken, delay: Duration) -> bool {
    token
        .run_until_cancelled(bitwarden_threading::time::sleep(delay))
        .await
        .is_some()
}

/// Returns the client if it still exists and is unlocked.
async fn upgrade_if_unlocked(client: &Weak<InternalClient>) -> Option<Client> {
    let client = Client {
        internal: client.upgrade()?,
    };
    is_unlocked(&client).await.then_some(client)
}

/// Checks for the user key in the key store and, on WASM, in the client's state. The TypeScript
/// clients clear the user key from their state on lock, but do not clear the key store of an SDK
/// client that they no longer use.
async fn is_unlocked(client: &Client) -> bool {
    if !client
        .internal
        .get_key_store()
        .context()
        .has_symmetric_key(SymmetricKeySlotId::User)
    {
        return false;
    }

    #[cfg(feature = "wasm")]
    {
        let bridge = client.km_state_bridge();
        if bridge.is_bridge_registered() && bridge.get_user_key().await.is_none() {
            return false;
        }
    }

    true
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};

    use super::*;
    use crate::{
        migration::MigrationNeed,
        runner::tests::{FakeMigration, FakeRun},
    };

    /// An unlocked client of a new user.
    pub(crate) async fn unlocked_client() -> (Client, UserId) {
        let client = Client::new(None);
        let user_id = UserId::new_v4();
        client
            .internal
            .init_user_id(user_id)
            .await
            .expect("the user ID is not set");
        #[allow(deprecated)]
        client
            .internal
            .get_key_store()
            .context_mut()
            .set_symmetric_key(
                SymmetricKeySlotId::User,
                SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            )
            .expect("the context is mutable");
        (client, user_id)
    }

    /// Returns whether the process-wide scheduler has a scheduled or running run of the user.
    pub(crate) fn is_scheduled(user_id: UserId) -> bool {
        SCHEDULER.user_run_states.contains(user_id)
    }

    /// A scheduler with one fake migration, and the number of its runs.
    fn fake_scheduler() -> (Arc<Scheduler>, Arc<AtomicUsize>) {
        let runs = Arc::new(AtomicUsize::new(0));
        let runs_in_migration = Arc::clone(&runs);
        let run: FakeRun = Arc::new(move |_| {
            runs_in_migration.fetch_add(1, Ordering::SeqCst);
        });
        let scheduler = Scheduler::new(move |_| {
            vec![Box::new(FakeMigration {
                need: MigrationNeed::Needed,
                run: Arc::clone(&run),
            })]
        });
        (Arc::new(scheduler), runs)
    }

    /// Paused time advances only when every task is idle, so the tasks that wake within `delay`
    /// finish before this returns.
    async fn wait_past(delay: Duration) {
        tokio::time::sleep(delay + Duration::from_secs(1)).await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_trigger_runs_once_after_the_trigger_delay_and_removes_the_entry() {
        let (client, user_id) = unlocked_client().await;
        let (scheduler, runs) = fake_scheduler();

        scheduler.trigger(&client);
        wait_past(TRIGGER_DELAY).await;
        wait_past(Duration::from_secs(24 * 60 * 60)).await;

        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert!(!scheduler.user_run_states.contains(user_id));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_trigger_during_the_trigger_delay_runs_once() {
        let (client, _) = unlocked_client().await;
        let (scheduler, runs) = fake_scheduler();

        scheduler.trigger(&client);
        tokio::time::sleep(TRIGGER_DELAY / 2).await;
        scheduler.trigger(&client);
        wait_past(TRIGGER_DELAY).await;

        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_trigger_without_a_user_id_schedules_nothing() {
        let client = Client::new(None);
        let (scheduler, runs) = fake_scheduler();

        scheduler.trigger(&client);
        wait_past(TRIGGER_DELAY).await;

        assert_eq!(runs.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_locked_client_removes_the_entry_without_a_run() {
        let (client, user_id) = unlocked_client().await;
        let (scheduler, runs) = fake_scheduler();
        scheduler.trigger(&client);
        client.internal.get_key_store().clear();

        wait_past(TRIGGER_DELAY).await;

        assert_eq!(runs.load(Ordering::SeqCst), 0);
        assert!(!scheduler.user_run_states.contains(user_id));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_dropped_client_removes_the_entry_without_a_run() {
        let (client, user_id) = unlocked_client().await;
        let (scheduler, runs) = fake_scheduler();
        scheduler.trigger(&client);
        drop(client);

        wait_past(TRIGGER_DELAY).await;

        assert_eq!(runs.load(Ordering::SeqCst), 0);
        assert!(!scheduler.user_run_states.contains(user_id));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_trigger_during_a_run_runs_again_after_the_trigger_delay() {
        let (client, user_id) = unlocked_client().await;
        let runs = Arc::new(AtomicUsize::new(0));
        let runs_in_migration = Arc::clone(&runs);
        // The first run triggers the scheduler that runs it.
        let scheduler = Arc::new_cyclic(|scheduler: &Weak<Scheduler>| {
            let scheduler = Weak::clone(scheduler);
            Scheduler::new(move |client| {
                let scheduler = Weak::clone(&scheduler);
                let client = client.clone();
                let runs = Arc::clone(&runs_in_migration);
                let run: FakeRun = Arc::new(move |_| {
                    if runs.fetch_add(1, Ordering::SeqCst) == 0 {
                        scheduler
                            .upgrade()
                            .expect("the test holds the scheduler")
                            .trigger(&client);
                    }
                });
                vec![Box::new(FakeMigration {
                    need: MigrationNeed::Needed,
                    run,
                })]
            })
        });

        scheduler.trigger(&client);
        wait_past(TRIGGER_DELAY).await;
        let runs_before_the_follow_up_delay = runs.load(Ordering::SeqCst);
        wait_past(TRIGGER_DELAY).await;

        assert_eq!(runs_before_the_follow_up_delay, 1);
        assert_eq!(runs.load(Ordering::SeqCst), 2);
        assert!(!scheduler.user_run_states.contains(user_id));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_trigger_after_a_run_runs_again() {
        let (client, _) = unlocked_client().await;
        let (scheduler, runs) = fake_scheduler();

        scheduler.trigger(&client);
        wait_past(TRIGGER_DELAY).await;
        scheduler.trigger(&client);
        wait_past(TRIGGER_DELAY).await;

        assert_eq!(runs.load(Ordering::SeqCst), 2);
    }
}
