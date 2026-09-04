//! # Shared Unlock Protocol
//!
//! Synchronizes vault lock state across multiple Bitwarden clients (web, browser extension,
//! desktop) running in the same session. When a user unlocks their vault on one client, the
//! unlock propagates to all connected clients.
//!
//! ## Peer Model
//!
//! Every client runs exactly one [`SharedUnlockPeer`]. Each peer knows the one peer above it in the
//! device hierarchy — its *leader* — and syncs to it, while also serving whichever peers sync to
//! it:
//!
//! ```text
//!   Web Client  ──syncs to──▶  Browser Extension  ──syncs to──▶  Desktop App
//!   CLI Client  ──syncs to──▶  Desktop App
//! ```
//!
//! The hierarchy decides who talks to whom, not who is in charge. There is no authoritative
//! participant: reconciliation is symmetric and the freshest state wins. A peer in the middle of
//! the chain relays simply by applying what it hears and advertising what it holds — the browser
//! extension needs no special handling for leading the web vault while following the desktop app.
//!
//! The desktop app is the only client with no leader; it exclusively serves.
//!
//! ## Messages
//!
//! There is one message, [`SharedUnlockSync`], carrying a user id and that device's
//! [`TimestampedLockState`]. It is sent in both directions.
//!
//! A peer sends one sync per logged-in user, to its leader and to every active peer:
//!
//! - immediately on [`SharedUnlockPeer::start`], so it does not wait an interval to be discovered,
//! - on every [`DeviceEvent`], so a manual lock or unlock propagates without delay, and
//! - every [`SYNC_INTERVAL`].
//! - as a reply to first sync connection
//!
//! ```text
//!   Peer                                      Peer above (leader)
//!     │                                          │
//!     │──Sync(user, state@date)─────────────────▶│  on start, on device event, every interval
//!     │                                          │  · applies the state if the date is newer
//!     │                                          │  · registers the sender as an active peer
//!     │                                          │
//!     │◀─Sync(user, state@date)──────────────────│  once on first contact, then on device
//!     │  · applies the state if the date is newer │  events and every interval
//!     │  · suppresses its vault timeout           │
//! ```
//!
//! ## Reconciliation
//!
//! On receiving a sync, a peer:
//!
//! 1. Drops it if the source is a web client whose origin does not match the user's vault URL. The
//!    origin that passed this check is kept with the peer, and the same check is applied again on
//!    the way out (see [Origin scoping](#origin-scoping)).
//! 2. Drops it if the user is not in [`SharedUnlockDriver::list_users`] — that is how a peer knows
//!    it has no account for a user, and it never advertises such a user either.
//! 3. Drops it if `changed_at` is older than the date this device has recorded. A user this device
//!    has recorded nothing for counts as date `0`.
//! 4. On an *equal* date, drops it unless it is a `Locked` arriving at an unlocked device. Equal
//!    dates mean two devices acted inside the same millisecond without having seen each other, so
//!    the tie is broken toward `Locked`: both sides then resolve it identically and converge
//!    without another round, and the ambiguous case fails closed rather than resurrecting an
//!    unlock.
//! 5. Otherwise records the incoming state *and its date*, and calls
//!    [`SharedUnlockDriver::lock_user`] or [`SharedUnlockDriver::unlock_user`] if — and only if —
//!    the state actually differs from what was recorded.
//!
//! ## Origin scoping
//!
//! A web peer is scoped to one origin, in both directions:
//!
//! - an incoming sync from a web source is dropped unless its origin is the vault URL of the user
//!   it carries, and
//! - an outgoing sync is withheld from a web peer unless the user's vault URL is the origin that
//!   peer was registered with — which covers the introductory reply on first contact as much as the
//!   periodic and device-event syncs.
//!
//! ## Keep-alive
//!
//! A sync received *from this peer's leader* also calls
//! [`SharedUnlockDriver::suppress_vault_timeout`] for [`SYNC_INTERVAL`] plus
//! [`VAULT_TIMEOUT_GRACE_PERIOD`], keeping the vault unlocked as long as the shared session is
//! active. Syncs from peers below do not suppress anything; they only mark the sender active.
//!
//! Peers that have not been heard from in [`PEER_STALE_AFTER`] are pruned and stop being synced to.
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

impl LockState {
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
            Endpoint::DesktopRenderer | Endpoint::DesktopMain => SharedUnlockClient::Desktop,
        }
    }
}
