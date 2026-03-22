use bitwarden_core::UserId;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tsify::Tsify;

mod drivers;
pub(crate) use drivers::*;
mod follower;
pub(crate) use follower::*;
mod leader;
pub(crate) use leader::*;
mod protocol;
pub(crate) use protocol::*;

pub const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserKey(ByteBuf);

impl UserKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl UserKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(ByteBuf::from(bytes))
    }
}

/// Represents the lock state of a user.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum LockState {
    /// The user is locked (does not have a user-key in memory).
    Locked,
    /// The user is unlocked (has a user-key in memory).
    Unlocked {
        /// The user-key of the unlocked user
        user_key: UserKey,
    },
}

/// The device (client) has several events that need to be reported to the shared unlock system.
/// This enum represents the events that need to be reported.
#[derive(Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum DeviceEvent {
    /// The user with the given user id has been locked manually in the UI
    ManualLock { user_id: UserId },
    /// The user with the given user id has been unlocked manually in the UI
    ManualUnlock { user_id: UserId, user_key: Vec<u8> },
    /// Runs scheduled every `HEARTBEAT_INTERVAL` to drive keep-alives
    Timer,
}
