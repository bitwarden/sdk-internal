//! Drivers that need to be implemented per platform for the shared unlock system.

use bitwarden_core::UserId;

use crate::{LockState, UserKey};

/// Trait that implements managing the lock state for users in the application
#[async_trait::async_trait]
pub trait UserLockManagement {
    /// Lock the user with the given ID.
    async fn lock_user(&self, user_id: UserId) -> Result<(), ()>;
    /// Unlock the user with the given ID.
    async fn unlock_user(&self, user_id: UserId, user_key: UserKey) -> Result<(), ()>;
    /// List all users that are currently locked or unlocked.
    async fn list_users(&self) -> Vec<UserId>;
    /// Get the lock state of the user with the given ID.
    async fn get_user_lock_state(&self, user_id: UserId) -> LockState;
    /// Get vault_url for the user with the given ID, if available. This is used to verify IPC
    /// message sources
    async fn get_vault_url(&self, user_id: UserId) -> Option<String>;
    /// Suppress the vault timeout for the given user until the specified duration from now.
    /// Called when a heartbeat response is received, keeping the shared session active.
    async fn suppress_vault_timeout(&self, user_id: UserId, until: std::time::Duration);
}

/// The LeaderDiscovery trait is responsible for discovering the leader's IPC endpoint, given the
/// current platform. There should only be one possible leader for any given device. For web
/// clients, there is only one browser extension, for browser extensions there is only one desktop
/// device, and for CLI clients there is also only one desktop device.
#[async_trait::async_trait]
pub trait LeaderDiscovery {
    /// Discover the leader and return its endpoint.
    async fn discover_leader(&self) -> Option<bitwarden_ipc::Endpoint>;
}
