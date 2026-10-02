//! The protocol's single message, and the timestamped lock state it carries.

use bitwarden_core::UserId;
use bitwarden_ipc::PayloadTypeName;
use serde::{Deserialize, Serialize};

use crate::LockState;

/// A user's lock state, together with when the reporting device entered it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TimestampedLockState {
    /// What lock state the device recorded
    pub lock_state: LockState,
    /// Milliseconds since the Unix epoch at which the device entered `lock_state`.
    pub changed_at: u64,
}

impl Default for TimestampedLockState {
    /// The state a peer advertises for a user it has not observed a transition for. The zero date
    /// loses every comparison, so this can never overwrite another peer; it exists so the receiving
    /// peer learns this one is alive and adds it to its active-peer map.
    fn default() -> Self {
        Self {
            lock_state: LockState::Locked,
            changed_at: 0,
        }
    }
}

impl TimestampedLockState {
    /// Whether this state, as reported by a peer, supersedes what the receiving device has
    /// recorded.
    ///
    /// A user the receiver has recorded nothing for counts as date `0`, so a peer's default state
    /// is ignored rather than mistaken for an authoritative lock.
    ///
    /// Equal dates are ambiguous: two devices acting inside the same millisecond, neither having
    /// seen the other yet. Those are broken toward `Locked`.
    pub(crate) fn supersedes(&self, recorded: Option<&TimestampedLockState>) -> bool {
        let recorded_at = recorded.map_or(0, |recorded| recorded.changed_at);
        match self.changed_at.cmp(&recorded_at) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => {
                matches!(self.lock_state, LockState::Locked)
                    && matches!(
                        recorded.map(|recorded| &recorded.lock_state),
                        Some(LockState::Unlocked { .. })
                    )
            }
        }
    }
}

/// The only message in the protocol, sent in both directions.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SharedUnlockSync {
    /// User whose lock state is being synchronized.
    pub user_id: UserId,
    /// The sending device's lock state for that user.
    pub state: TimestampedLockState,
}

impl PayloadTypeName for SharedUnlockSync {
    const PAYLOAD_TYPE_NAME: &'static str = "password-manager.shared-unlock.sync";
}
#[cfg(test)]
mod tests {
    use bitwarden_crypto::SymmetricCryptoKey;
    use bitwarden_encoding::B64;

    use super::*;

    fn key() -> SymmetricCryptoKey {
        SymmetricCryptoKey::try_from(B64::from([1u8; 64].to_vec()))
            .expect("A 64-byte key should be valid")
    }

    fn locked_at(changed_at: u64) -> TimestampedLockState {
        TimestampedLockState {
            lock_state: LockState::Locked,
            changed_at,
        }
    }

    fn unlocked_at(changed_at: u64) -> TimestampedLockState {
        TimestampedLockState {
            lock_state: LockState::Unlocked { user_key: key() },
            changed_at,
        }
    }

    #[test]
    fn a_newer_date_supersedes() {
        assert!(unlocked_at(2).supersedes(Some(&locked_at(1))));
    }

    #[test]
    fn an_older_date_does_not() {
        assert!(!unlocked_at(1).supersedes(Some(&locked_at(2))));
    }

    #[test]
    fn nothing_recorded_counts_as_date_zero() {
        assert!(unlocked_at(1).supersedes(None));
        assert!(
            !locked_at(0).supersedes(None),
            "The default advertisement must not read as an authoritative lock"
        );
    }

    #[test]
    fn an_equal_date_resolves_toward_locked() {
        assert!(
            locked_at(5).supersedes(Some(&unlocked_at(5))),
            "A tie must fail closed"
        );
        assert!(
            !unlocked_at(5).supersedes(Some(&locked_at(5))),
            "and must resolve the same way seen from the other side"
        );
    }

    #[test]
    fn an_equal_date_with_the_same_state_is_a_no_op() {
        assert!(!locked_at(5).supersedes(Some(&locked_at(5))));
        assert!(!unlocked_at(5).supersedes(Some(&unlocked_at(5))));
    }
}
