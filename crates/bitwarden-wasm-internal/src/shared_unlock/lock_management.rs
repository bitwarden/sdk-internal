use bitwarden_core::UserId;
use wasm_bindgen::prelude::wasm_bindgen;

/// Trait that implements managing the lock state for users in the application
pub trait UserLockManagement {
    /// Lock the user with the given ID.
    async fn lock_user(&self, user_id: UserId) -> Result<(), ()>;
    /// Unlock the user with the given ID.
    async fn unlock_user(&self, user_id: UserId, user_key: Vec<u8>) -> Result<(), ()>;
    /// List all users that are currently locked or unlocked.
    async fn list_users(&self) -> Vec<UserId>;
    /// Get the lock state of the user with the given ID.
    async fn get_user_lock_state(&self, user_id: UserId) -> LockState;
}

/// Represents the lock state of a user.
pub enum LockState {
    /// The user is locked (does not have a user-key in memory).
    Locked,
    /// The user is unlocked (has a user-key in memory).
    Unlocked {
        /// The user-key of the unlocked user
        key: Vec<u8>,
    },
}
