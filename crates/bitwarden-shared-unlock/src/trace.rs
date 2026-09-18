//! Names of the Chrome DevTools performance tracks this crate draws on.
//!
//! ```text
//!   ── Shared Unlock ────────────────────────────
//!       Announces    ▏▏     ▏▏▏        ▏▏      ◀ every sync sent and applied
//!       Biometrics         ▉▉▉▉▉▉             ◀ biometrics requests over IPC
//! ```
//!
//! The underlying IPC traffic shows up separately on the `IPC` track group, so an announce can be
//! lined up against the message that carried it.

/// Track group holding everything shared unlock records.
pub(crate) const GROUP: &str = "Shared Unlock";

/// Lock-state syncs, in both directions.
pub(crate) const ANNOUNCES_TRACK: &str = "Announces";

/// Biometrics status checks, unlocks and UV checks proxied over IPC. Only the wasm clients proxy
/// biometrics, so the track exists only there.
#[cfg(feature = "wasm")]
pub(crate) const BIOMETRICS_TRACK: &str = "Biometrics";
