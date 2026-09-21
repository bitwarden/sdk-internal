//! Drivers that need to be implemented per platform for the shared unlock system.

use bitwarden_core::UserId;
use bitwarden_crypto::SymmetricCryptoKey;

/// Trait that implmeents the device's shared unlock driver. These functions need to be implemented
/// in order to allow the shared unlock system to function.
#[async_trait::async_trait]
pub trait SharedUnlockDriver {
    /// Lock the user with the given ID.
    async fn lock_user(&self, user_id: UserId) -> Result<(), ()>;
    /// Unlock the user with the given ID.
    async fn unlock_user(&self, user_id: UserId, user_key: SymmetricCryptoKey) -> Result<(), ()>;
    /// List all users this device has an account for, locked or unlocked.
    async fn list_users(&self) -> Vec<UserId>;
    /// Get vault_url for the user with the given ID, if available. This is used to verify IPC
    /// message sources
    async fn get_vault_url(&self, user_id: UserId) -> Option<String>;
    /// Suppress the vault timeout for the given user for the specified duration.
    /// Called when a sync is received from this device's leader, keeping the shared session active.
    async fn suppress_vault_timeout(
        &self,
        user_id: UserId,
        suppression_duration: std::time::Duration,
    );
    /// Discovers the endpoint of the peer above this one in the device hierarchy or none
    /// if this device is at the top of the hierarchy. The local peer disables vault timeout
    /// if it is not at the top of the hierarchy.
    async fn discover_leader(&self) -> Option<bitwarden_ipc::Endpoint>;
}
