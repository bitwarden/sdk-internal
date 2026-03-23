//! Drivers that need to be implemented per platform for the shared unlock system.

use bitwarden_core::UserId;

use crate::{LockState, Message, UserKey};

/// Trait that implements managing the lock state for users in the application
pub trait UserLockManagement {
    /// Lock the user with the given ID.
    async fn lock_user(&self, user_id: UserId) -> Result<(), ()>;
    /// Unlock the user with the given ID.
    async fn unlock_user(&self, user_id: UserId, user_key: UserKey) -> Result<(), ()>;
    /// List all users that are currently locked or unlocked.
    async fn list_users(&self) -> Vec<UserId>;
    /// Get the lock state of the user with the given ID.
    async fn get_user_lock_state(&self, user_id: UserId) -> LockState;
}

/// The HeartbeatResponseHandler gets called on every heartbeat response received by the leader.
/// On platforms that support vault timeout, such as web, browser, desktop, this handler
/// should supress the vault timeout until the next heartbeat, i.e while the session is active.
pub trait HeartbeatResponseHandler {
    /// Run a function on every heartbeat response.
    async fn handle_heartbeat(&self, user_id: UserId);
}

/// The MessageSender trait is responsible for sending messages to other devices. The implementation
/// of this trait should call the IPC system
pub trait MessageSender {
    /// Send a message to the given recipient.
    fn send_message(&self, message: Message, recipient: bitwarden_ipc::Endpoint);
}

/// The LeaderDiscovery trait is responsible for discovering the leader's IPC endpoint, given the
/// current platform. There should only be one possible leader for any given device. For web
/// clients, there is only one browser extension, for browser extensions there is only one desktop
/// device, and for CLI clients there is also only one desktop device.
pub trait LeaderDiscovery {
    /// Discover the leader and return its endpoint.
    async fn discover_leader(&self) -> Option<bitwarden_ipc::Endpoint>;
}
