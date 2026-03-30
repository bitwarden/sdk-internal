//! # Shared Unlock Protocol
//!
//! Synchronizes vault lock state across multiple Bitwarden clients (web, browser extension,
//! desktop) running in the same session. When a user unlocks their vault on one client, the
//! unlock propagates to all connected clients.
//!
//! ## Leader-Follower Model
//!
//! The protocol uses a leader-follower architecture where each client type has exactly one
//! leader determined by the device hierarchy:
//!
//! ```text
//!   Web Client  ──follows──▶  Browser Extension  ──follows──▶  Desktop App
//!   CLI Client  ──follows──▶  Desktop App
//! ```
//!
//! - **Leader**: Holds authoritative lock state, broadcasts state changes to all followers.
//! - **Follower**: Reports local state changes to its leader, applies authoritative updates from
//!   the leader.
//!
//! A client can be both a leader (to clients below it) and a follower (to the client above it)
//! simultaneously. For example, the browser extension leads web clients while following the
//! desktop app.
//!
//! ## Message Types
//!
//! All messages are serialized as CBOR and sent over the IPC transport.
//!
//! | Message          | Direction          | Purpose                                           |
//! |------------------|--------------------|---------------------------------------------------|
//! | `StartSession`   | Follower → Leader  | Announce presence with current lock state         |
//! | `LockStateUpdate`| Bidirectional      | Propagate lock/unlock events                      |
//! | `HeartBeat`      | Bidirectional      | Keep session alive, suppress vault timeout        |
//!
//! ## Session Lifecycle
//!
//! ### Follower Startup
//!
//! ```text
//!   Follower                          Leader
//!     │                                 │
//!     │──StartSession(user, state)─────▶│  Follower announces itself
//!     │                                 │  Leader applies state if unlocked
//!     │◀─LockStateUpdate(user, state)───│  Leader responds with authoritative state
//!     │                                 │
//! ```
//!
//! On startup, the follower sends a `StartSession` for each logged-in user. If the follower
//! is unlocked and the leader is locked, the leader unlocks using the provided user key.
//! The leader always responds with a `LockStateUpdate` containing the authoritative state.
//!
//! ### Lock/Unlock Propagation
//!
//! **User unlocks on follower:**
//!
//! ```text
//!   Follower A                        Leader                         Follower B
//!     │                                 │                                │
//!     │──LockStateUpdate(Unlocked)─────▶│                                │
//!     │                                 │──unlocks locally──             │
//!     │◀─LockStateUpdate(Unlocked)──────│                                │
//!     │                                 │──LockStateUpdate(Unlocked)────▶│
//!     │                                 │                                │──unlocks locally──
//! ```
//!
//! **User locks on leader (via device event):**
//!
//! ```text
//!   Leader                          Follower A                     Follower B
//!     │                                 │                                │
//!     │──LockStateUpdate(Locked)───────▶│                                │
//!     │──LockStateUpdate(Locked)────────┼───────────────────────────────▶│
//!     │                                 │──locks locally──               │──locks locally──
//! ```
//!
//! ### Heartbeat Keep-Alive
//!
//! ```text
//!   Follower                          Leader
//!     │                                 │
//!     │──HeartBeat(user)───────────────▶│  Every N seconds
//!     │                                 │  Leader updates last-seen timestamp
//!     │◀─HeartBeat(user)────────────────│  Leader echoes back
//!     │──suppresses vault timeout──     │
//!     │                                 │
//! ```
//!
//! The follower sends a `HeartBeat` for each logged-in user every [`HEARTBEAT_INTERVAL`]
//! On receiving the echo, the follower suppresses its vault timeout timer,
//! keeping the vault unlocked as long as the session is active. Stale sessions are pruned.

use bitwarden_core::UserId;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

mod drivers;
pub use drivers::*;
mod follower;
pub use follower::*;
mod leader;
pub use leader::*;
mod message;
pub use message::*;

/// Interval used by followers to send heartbeat keep-alive messages to their leader.
pub const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(test)]
mod tests;

/// Wrapper type containing a serialized user key used for unlock propagation.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserKey(ByteBuf);

impl UserKey {
    /// Returns the raw user key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Creates a user key wrapper from raw key bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(ByteBuf::from(bytes))
    }
}

impl std::fmt::Debug for UserKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("UserKey").field(&"<redacted>").finish()
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
#[derive(Serialize, Deserialize)]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub enum DeviceEvent {
    /// The user with the given user id has been locked manually in the UI
    ManualLock {
        /// User whose vault was manually locked.
        user_id: UserId,
    },
    /// The user with the given user id has been unlocked manually in the UI
    ManualUnlock {
        /// User whose vault was manually unlocked.
        user_id: UserId,
        /// Raw user key bytes used to unlock the vault.
        user_key: Vec<u8>,
    },
    /// Runs scheduled every `HEARTBEAT_INTERVAL` to drive keep-alives
    Timer,
}

/// Re-export types to make sure wasm_bindgen picks them up
#[cfg(feature = "wasm")]
pub mod wasm;
