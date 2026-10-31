//! Schedules the background migrations of each user.

use std::{
    sync::{Arc, LazyLock, Weak},
    time::Duration,
};

use bitwarden_core::{
    Client, UserId,
    client::internal::InternalClient,
    key_management::{SymmetricKeySlotId, UnlockHandler},
};
use bitwarden_threading::cancellation_token::CancellationToken;
use tokio::sync::oneshot;

use crate::{
    migration::{Migration, run_migrations},
    user_run_states::UserRunStates,
};

/// Gives the sync data time to reach state before the run.
const TRIGGER_DELAY: Duration = Duration::from_secs(5);
const RECURRING_DELAY: Duration = Duration::from_secs(24 * 60 * 60);

/// Global to the process, not per [`Client`], because the TypeScript clients replace the SDK client
/// each time the account's keys change in their state.
static SCHEDULER: LazyLock<Arc<Scheduler>> =
    LazyLock::new(|| Arc::new(Scheduler::new(Migration::all)));

/// Schedules the background migrations of the client's user after a short delay, replacing a
/// scheduled run that has not started.
///
/// Does not schedule a run while a run is in progress, for example when the server pushes a sync to
/// the client before the run ends.
pub fn trigger_background_migrations(client: &Client) {
    SCHEDULER.trigger(client);
}

/// Schedules the background migrations after each unlock.
pub struct EncryptedMigratorUnlockHandler;

impl UnlockHandler for EncryptedMigratorUnlockHandler {
    fn on_unlock(&self, client: &Client) {
        trigger_background_migrations(client);
    }
}

type MakeMigrations = dyn Fn(&Client) -> Vec<Migration> + Send + Sync;

struct Scheduler {
    user_run_states: UserRunStates,
    make_migrations: Box<MakeMigrations>,
}

impl Scheduler {
    fn new(make_migrations: impl Fn(&Client) -> Vec<Migration> + Send + Sync + 'static) -> Self {
        Self {
            user_run_states: UserRunStates::default(),
            make_migrations: Box::new(make_migrations),
        }
    }

    fn trigger(self: &Arc<Self>, client: &Client) {
        let Some(user_id) = client.internal.get_user_id() else {
            return;
        };
        if let Some(token) = self.user_run_states.try_schedule(user_id) {
            self.spawn_delayed_run(
                Arc::downgrade(&client.internal),
                user_id,
                token,
                TRIGGER_DELAY,
            );
        }
    }

    /// Spawns a task that runs the migrations after `delay`, then schedules the next run.
    ///
    /// The task holds only a weak reference while it waits, so it does not keep a dropped client
    /// and its keys in memory.
    fn spawn_delayed_run(
        self: &Arc<Self>,
        client: Weak<InternalClient>,
        user_id: UserId,
        token: CancellationToken,
        delay: Duration,
    ) {
        let scheduler = Arc::clone(self);
        bitwarden_threading::spawn(async move {
            if !wait_unless_replaced(&token, delay).await {
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
            scheduler
                .schedule_recurring_run_if_unlocked(&client, user_id, &token)
                .await;
        });
    }

    /// Runs the migrations in a separate task and returns when the task ends, also when a
    /// migration panics.
    async fn run_background_migrations(&self, client: &Client) {
        let (finished_sender, finished_receiver) = oneshot::channel::<()>();
        let migrations = (self.make_migrations)(client);
        bitwarden_threading::spawn(async move {
            let _finished_sender = finished_sender;
            run_migrations(&migrations).await;
        });
        // The sender never sends, so the receiver resolves with an error once the task drops it.
        let _ = finished_receiver.await;
    }

    /// Schedules the next run after [`RECURRING_DELAY`] if the client is unlocked. Otherwise
    /// removes the user's entry, and the next unlock schedules a new run.
    async fn schedule_recurring_run_if_unlocked(
        self: &Arc<Self>,
        client: &Client,
        user_id: UserId,
        token: &CancellationToken,
    ) {
        if !is_unlocked(client).await {
            self.user_run_states.remove(user_id, token);
            return;
        }
        let next = self.user_run_states.mark_next_run_scheduled(user_id);
        self.spawn_delayed_run(
            Arc::downgrade(&client.internal),
            user_id,
            next,
            RECURRING_DELAY,
        );
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
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};

    use super::*;

    /// An unlocked client of a new user.
    async fn unlocked_client() -> (Client, UserId) {
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

    /// A scheduler with one fake migration that calls `on_run`, and the number of its runs.
    fn fake_scheduler(
        on_run: impl Fn() + Send + Sync + 'static,
    ) -> (Arc<Scheduler>, Arc<AtomicUsize>) {
        let runs = Arc::new(AtomicUsize::new(0));
        let runs_in_migration = Arc::clone(&runs);
        let run: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            runs_in_migration.fetch_add(1, Ordering::SeqCst);
            on_run();
        });
        let scheduler = Scheduler::new(move |_| vec![Migration::Fake(Arc::clone(&run))]);
        (Arc::new(scheduler), runs)
    }

    /// Paused time advances only when every task is idle, so the tasks that wake within `delay`
    /// finish before this returns.
    async fn wait_past(delay: Duration) {
        tokio::time::sleep(delay + Duration::from_secs(1)).await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_trigger_runs_after_the_trigger_delay_and_again_after_the_recurring_delay() {
        let (client, user_id) = unlocked_client().await;
        let (scheduler, runs) = fake_scheduler(|| {});

        scheduler.trigger(&client);
        wait_past(TRIGGER_DELAY).await;
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        wait_past(RECURRING_DELAY).await;

        assert_eq!(runs.load(Ordering::SeqCst), 2);
        assert!(scheduler.user_run_states.contains(user_id));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_trigger_during_the_trigger_delay_runs_once() {
        let (client, _) = unlocked_client().await;
        let (scheduler, runs) = fake_scheduler(|| {});

        scheduler.trigger(&client);
        tokio::time::sleep(TRIGGER_DELAY / 2).await;
        scheduler.trigger(&client);
        wait_past(TRIGGER_DELAY).await;

        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_trigger_without_a_user_id_schedules_nothing() {
        let client = Client::new(None);
        let (scheduler, runs) = fake_scheduler(|| {});

        scheduler.trigger(&client);
        wait_past(TRIGGER_DELAY).await;

        assert_eq!(runs.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_locked_client_removes_the_entry_without_a_run() {
        let (client, user_id) = unlocked_client().await;
        let (scheduler, runs) = fake_scheduler(|| {});
        scheduler.trigger(&client);
        client.internal.get_key_store().clear();

        wait_past(TRIGGER_DELAY).await;

        assert_eq!(runs.load(Ordering::SeqCst), 0);
        assert!(!scheduler.user_run_states.contains(user_id));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_dropped_client_removes_the_entry_without_a_run() {
        let (client, user_id) = unlocked_client().await;
        let (scheduler, runs) = fake_scheduler(|| {});
        scheduler.trigger(&client);
        drop(client);

        wait_past(TRIGGER_DELAY).await;

        assert_eq!(runs.load(Ordering::SeqCst), 0);
        assert!(!scheduler.user_run_states.contains(user_id));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_client_locked_during_the_run_schedules_no_next_run() {
        let (client, user_id) = unlocked_client().await;
        let key_store = client.internal.get_key_store().clone();
        let (scheduler, runs) = fake_scheduler(move || key_store.clear());

        scheduler.trigger(&client);
        wait_past(TRIGGER_DELAY).await;

        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert!(!scheduler.user_run_states.contains(user_id));
    }
}
