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
//!     |◀─LockStateUpdate────────────────│  Leader always sends an authoritative state update to prevent desyncs
//!     │──suppresses vault timeout──     │
//!     │                                 │
//! ```
//!
//! The follower sends a `HeartBeat` for each logged-in user every [`HEARTBEAT_INTERVAL`]
//! On receiving the echo, the follower suppresses its vault timeout timer,
//! keeping the vault unlocked as long as the session is active. Stale sessions are pruned.
//!
//! ## Security Definitions
//!
//! - Attacker Model:
//!   - Attacker gains user-space access to the device while the vault has been locked (steals the
//!     device)
//! - Security Goal:
//!   - Attacker cannot gain access to the vault key material
//!
//! This security definition is aimed at stolen or seized devices. Forensics should not uncover
//! (passively) recorded or otherwise left behind key material. The IPC encryption prevents such a
//! compromise.
//!
//! There is no further protection provided against active attackers running in userspace while the
//! vault is unlocked on any of the clients on the device.
//!
//! - Attacker Model:
//!   - Attacker controls a website that is not the web vault
//! - Security Goal:
//!   - Attacker cannot gain access to the vault key material
//!
//! This is met by origin validation, which is enforced on both the receive and the send path — see
//! [Origin scoping](#origin-scoping). Validating only what arrives would not meet the goal: a peer
//! that is registered after one validated sync goes on to be sent every user's state.

use bitwarden_core::UserId;
use bitwarden_crypto::SymmetricCryptoKey;
use bitwarden_ipc::Endpoint;
use serde::{Deserialize, Serialize};

mod active_peers;
mod drivers;
pub use drivers::*;
mod message;
pub use message::*;
mod peer;
pub use peer::*;
mod timing;

/// Wasm support module for shared unlock
#[cfg(feature = "wasm")]
pub mod wasm;

/// Interval at which a peer syncs its lock state to its leader and to its active peers.
pub const SYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
/// Additional grace period added to the vault timeout when suppressing it on a sync from the
/// leader.
pub const VAULT_TIMEOUT_GRACE_PERIOD: std::time::Duration = std::time::Duration::from_secs(2);
/// How long a peer may go without syncing before it is pruned and no longer synced to.
pub const PEER_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

/// Represents the lock state of a user.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum LockState {
    /// The user is locked (does not have a user-key in memory).
    Locked,
    /// The user is unlocked (has a user-key in memory).
    Unlocked {
        /// The user-key of the unlocked user
        user_key: SymmetricCryptoKey,
    },
}

/// A peer's lock state for a user, stripped of the key material [`LockState::Unlocked`] carries.
///
/// Reported to the driver on every sync this device accepts, so a client can tell "a peer
/// answered, and it is locked" from "no peer answered at all".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[bitwarden_ffi::wasm_record]
pub enum PeerLockState {
    /// The peer reported the user as locked.
    Locked,
    /// The peer reported the user as unlocked.
    Unlocked,
}

impl LockState {
    /// The state as reported to a driver, which is never handed key material.
    pub(crate) fn peer_state(&self) -> PeerLockState {
        match self {
            LockState::Locked => PeerLockState::Locked,
            LockState::Unlocked { .. } => PeerLockState::Unlocked,
        }
    }

    /// Names the state without touching the key it may carry, so it is safe to log.
    pub(crate) fn describe(&self) -> &'static str {
        match self {
            LockState::Locked => "locked",
            LockState::Unlocked { .. } => "unlocked",
        }
    }
}

/// The device (client) has several events that need to be reported to the shared unlock system.
/// This enum represents the events that need to be reported.
#[derive(Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
#[bitwarden_ffi::wasm_record]
pub enum DeviceEvent {
    /// The user with the given user id has been locked manually in the UI
    ManualLock {
        #[zeroize(skip)]
        /// User whose vault was manually locked.
        user_id: UserId,
    },
    /// The user with the given user id has been unlocked manually in the UI
    ManualUnlock {
        #[zeroize(skip)]
        /// User whose vault was manually unlocked.
        user_id: UserId,
        /// Raw user key bytes used to unlock the vault.
        #[cfg_attr(feature = "wasm", tsify(type = "SymmetricKey"))]
        user_key: SymmetricCryptoKey,
    },
}

/// A kind of client a peer may share unlock state with, independent of the IPC endpoint variants
/// that address its individual contexts (foreground/background, renderer/main).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[bitwarden_ffi::wasm_record]
pub enum SharedUnlockClient {
    /// The browser extension, in any of its contexts.
    Browser,
    /// The command-line interface, in any of its invocations.
    Cli,
    /// The desktop app, in any of its processes.
    Desktop,
    /// A web vault tab.
    Web,
}

impl SharedUnlockClient {
    /// The client an endpoint belongs to.
    pub(crate) fn of_endpoint(endpoint: &Endpoint) -> Self {
        match endpoint {
            Endpoint::Web { .. } => SharedUnlockClient::Web,
            Endpoint::BrowserForeground { .. } | Endpoint::BrowserBackground { .. } => {
                SharedUnlockClient::Browser
            }
            Endpoint::Cli { .. } => SharedUnlockClient::Cli,
            Endpoint::DesktopRenderer | Endpoint::DesktopMain => SharedUnlockClient::Desktop,
        }
    }
}
