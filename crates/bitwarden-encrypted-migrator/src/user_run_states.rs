use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard, Weak},
};

use bitwarden_core::{UserId, client::internal::InternalClient};
use bitwarden_threading::cancellation_token::CancellationToken;

enum RunState {
    Scheduled(CancellationToken),
    /// `follow_up` is the client of the last trigger during the run. The trigger can come from
    /// another client than the run, because the TypeScript clients replace the SDK client.
    InProgress {
        follow_up: Option<Weak<InternalClient>>,
    },
}

/// One entry per user whose run is scheduled or in progress.
///
/// Replacing a scheduled entry cancels its token under the same lock. A task checks its token
/// before it changes an entry, so a replaced task does not change the newer entry.
#[derive(Default)]
pub(crate) struct UserRunStates {
    entries: Mutex<HashMap<UserId, RunState>>,
}

impl UserRunStates {
    /// Replaces the user's scheduled entry with a new one and returns its token. While a run is in
    /// progress, stores `client` for a follow-up run and returns `None`.
    pub(crate) fn try_schedule(
        &self,
        user_id: UserId,
        client: &Weak<InternalClient>,
    ) -> Option<CancellationToken> {
        let mut entries = self.entries();
        if let Some(RunState::InProgress { follow_up }) = entries.get_mut(&user_id) {
            *follow_up = Some(Weak::clone(client));
            return None;
        }
        if let Some(RunState::Scheduled(replaced)) = entries.get(&user_id) {
            replaced.cancel();
        }
        let token = CancellationToken::new();
        entries.insert(user_id, RunState::Scheduled(token.clone()));
        Some(token)
    }

    /// Marks the run as in progress. Returns `false` if `token` is canceled.
    pub(crate) fn try_mark_run_in_progress(
        &self,
        user_id: UserId,
        token: &CancellationToken,
    ) -> bool {
        let mut entries = self.entries();
        if token.is_cancelled() {
            return false;
        }
        entries.insert(user_id, RunState::InProgress { follow_up: None });
        true
    }

    /// Ends the user's run in progress. After a trigger during the run, replaces the entry with a
    /// scheduled entry and returns its token and the client of the trigger. Otherwise, removes the
    /// entry.
    pub(crate) fn finish_run(
        &self,
        user_id: UserId,
    ) -> Option<(CancellationToken, Weak<InternalClient>)> {
        let mut entries = self.entries();
        let Some(RunState::InProgress {
            follow_up: Some(client),
        }) = entries.remove(&user_id)
        else {
            return None;
        };
        let token = CancellationToken::new();
        entries.insert(user_id, RunState::Scheduled(token.clone()));
        Some((token, client))
    }

    /// Removes the user's scheduled entry, unless `token` is canceled.
    pub(crate) fn remove(&self, user_id: UserId, token: &CancellationToken) {
        let mut entries = self.entries();
        if !token.is_cancelled() {
            entries.remove(&user_id);
        }
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, user_id: UserId) -> bool {
        self.entries().contains_key(&user_id)
    }

    fn entries(&self) -> MutexGuard<'_, HashMap<UserId, RunState>> {
        self.entries.lock().expect("Mutex is not poisoned")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_core::Client;

    use super::*;

    /// A client reference for the tests that do not read it.
    fn no_client() -> Weak<InternalClient> {
        Weak::new()
    }

    #[test]
    fn test_try_schedule_cancels_the_scheduled_token() {
        let run_states = UserRunStates::default();
        let user_id = UserId::new_v4();
        let first = run_states
            .try_schedule(user_id, &no_client())
            .expect("no run is in progress");
        let second = run_states
            .try_schedule(user_id, &no_client())
            .expect("no run is in progress");

        assert!(first.is_cancelled());
        assert!(!run_states.try_mark_run_in_progress(user_id, &first));
        assert!(run_states.try_mark_run_in_progress(user_id, &second));
    }

    #[test]
    fn test_try_schedule_during_a_run_returns_none() {
        let run_states = UserRunStates::default();
        let user_id = UserId::new_v4();
        let token = run_states
            .try_schedule(user_id, &no_client())
            .expect("no run is in progress");
        assert!(run_states.try_mark_run_in_progress(user_id, &token));

        assert!(run_states.try_schedule(user_id, &no_client()).is_none());
    }

    #[test]
    fn test_remove_removes_the_scheduled_entry() {
        let run_states = UserRunStates::default();
        let user_id = UserId::new_v4();
        let token = run_states
            .try_schedule(user_id, &no_client())
            .expect("no run is in progress");

        run_states.remove(user_id, &token);

        assert!(!run_states.contains(user_id));
    }

    #[test]
    fn test_finish_run_without_a_trigger_during_the_run_removes_the_entry() {
        let run_states = UserRunStates::default();
        let user_id = UserId::new_v4();
        let token = run_states
            .try_schedule(user_id, &no_client())
            .expect("no run is in progress");
        assert!(run_states.try_mark_run_in_progress(user_id, &token));

        assert!(run_states.finish_run(user_id).is_none());
        assert!(!run_states.contains(user_id));
    }

    #[test]
    fn test_finish_run_after_triggers_during_the_run_schedules_a_follow_up_with_the_last_client() {
        let run_states = UserRunStates::default();
        let user_id = UserId::new_v4();
        let first_client = Client::new(None);
        let last_client = Client::new(None);
        let token = run_states
            .try_schedule(user_id, &no_client())
            .expect("no run is in progress");
        assert!(run_states.try_mark_run_in_progress(user_id, &token));
        assert!(
            run_states
                .try_schedule(user_id, &Arc::downgrade(&first_client.internal))
                .is_none()
        );
        assert!(
            run_states
                .try_schedule(user_id, &Arc::downgrade(&last_client.internal))
                .is_none()
        );

        let (follow_up, client) = run_states
            .finish_run(user_id)
            .expect("a trigger during the run sets a follow-up");

        assert!(Weak::ptr_eq(
            &client,
            &Arc::downgrade(&last_client.internal)
        ));
        assert!(run_states.try_mark_run_in_progress(user_id, &follow_up));
    }

    #[test]
    fn test_remove_with_a_replaced_token_keeps_the_newer_entry() {
        let run_states = UserRunStates::default();
        let user_id = UserId::new_v4();
        let replaced = run_states
            .try_schedule(user_id, &no_client())
            .expect("no run is in progress");
        run_states
            .try_schedule(user_id, &no_client())
            .expect("no run is in progress");

        run_states.remove(user_id, &replaced);

        assert!(run_states.contains(user_id));
    }
}
