use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};

use bitwarden_core::UserId;
use bitwarden_threading::cancellation_token::CancellationToken;

enum RunState {
    Scheduled(CancellationToken),
    InProgress,
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
    /// Replaces the user's scheduled entry with a new one and returns its token. Returns `None`
    /// while a run is in progress.
    pub(crate) fn try_schedule(&self, user_id: UserId) -> Option<CancellationToken> {
        let mut entries = self.entries();
        if let Some(RunState::InProgress) = entries.get(&user_id) {
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
        entries.insert(user_id, RunState::InProgress);
        true
    }

    /// Replaces the entry of the run in progress with the next scheduled run and returns its token.
    pub(crate) fn mark_next_run_scheduled(&self, user_id: UserId) -> CancellationToken {
        let token = CancellationToken::new();
        self.entries()
            .insert(user_id, RunState::Scheduled(token.clone()));
        token
    }

    /// Removes the user's entry, unless `token` is canceled. Also removes the entry of a run in
    /// progress, because a trigger does not cancel its token.
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
    use super::*;

    #[test]
    fn test_try_schedule_cancels_the_scheduled_token() {
        let run_states = UserRunStates::default();
        let user_id = UserId::new_v4();
        let first = run_states
            .try_schedule(user_id)
            .expect("no run is in progress");
        let second = run_states
            .try_schedule(user_id)
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
            .try_schedule(user_id)
            .expect("no run is in progress");
        assert!(run_states.try_mark_run_in_progress(user_id, &token));

        assert!(run_states.try_schedule(user_id).is_none());
    }

    #[test]
    fn test_try_schedule_after_a_run_cancels_the_recurring_token() {
        let run_states = UserRunStates::default();
        let user_id = UserId::new_v4();
        let token = run_states
            .try_schedule(user_id)
            .expect("no run is in progress");
        assert!(run_states.try_mark_run_in_progress(user_id, &token));
        let recurring = run_states.mark_next_run_scheduled(user_id);

        let triggered = run_states
            .try_schedule(user_id)
            .expect("no run is in progress");

        assert!(recurring.is_cancelled());
        assert!(run_states.try_mark_run_in_progress(user_id, &triggered));
    }

    #[test]
    fn test_remove_removes_the_scheduled_entry() {
        let run_states = UserRunStates::default();
        let user_id = UserId::new_v4();
        let token = run_states
            .try_schedule(user_id)
            .expect("no run is in progress");

        run_states.remove(user_id, &token);

        assert!(!run_states.contains(user_id));
    }

    #[test]
    fn test_remove_during_a_run_removes_the_entry() {
        let run_states = UserRunStates::default();
        let user_id = UserId::new_v4();
        let token = run_states
            .try_schedule(user_id)
            .expect("no run is in progress");
        assert!(run_states.try_mark_run_in_progress(user_id, &token));

        run_states.remove(user_id, &token);

        assert!(!run_states.contains(user_id));
    }

    #[test]
    fn test_remove_with_a_replaced_token_keeps_the_newer_entry() {
        let run_states = UserRunStates::default();
        let user_id = UserId::new_v4();
        let replaced = run_states
            .try_schedule(user_id)
            .expect("no run is in progress");
        run_states
            .try_schedule(user_id)
            .expect("no run is in progress");

        run_states.remove(user_id, &replaced);

        assert!(run_states.contains(user_id));
    }
}
