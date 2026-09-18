//! Names of the Chrome DevTools performance tracks this crate draws on.
//!
//! ```text
//!   ── Unlock ───────────────────────────────────
//!       Session keys    ▉▉      ▉▉▉      ▏      ◀ minting, unlocking, invalidating
//! ```
//!
//! Session-key unlock is only reachable from the CLI, which is a native target where DevTools
//! draws nothing — but entries are debug-logged through `tracing` on every target, so they still
//! land in the flight recorder.

/// Track group holding everything unlock records.
pub(crate) const GROUP: &str = "Unlock";

/// The session-key lifecycle: minting one for the next invocation, unlocking with it, and
/// invalidating it on lock.
pub(crate) const SESSION_KEYS_TRACK: &str = "Session keys";
