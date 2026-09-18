//! Names of the Chrome DevTools performance tracks this crate draws on.
//!
//! ```text
//!   ── IPC ──────────────────────────────────────
//!       Messages   ▏▏▏▏   ▏▏  ▏▏▏▏   ▏▏      ◀ every message in and out
//!       Noise      ▉▉▉      ▉   ▏          ◀ handshakes, inbound decrypts, teardowns
//! ```
//!
//! See [`bitwarden_performance_tracking`] for what an entry is and when it is visible.

/// Track group holding everything IPC records.
pub(crate) const GROUP: &str = "IPC";

/// Individual messages, in both directions.
pub(crate) const MESSAGES_TRACK: &str = "Messages";

/// Noise session lifecycle — handshakes, re-handshakes, invalidations — plus the decryption of
/// each inbound message, which is the only part of receiving a message that costs anything.
pub(crate) const NOISE_TRACK: &str = "Noise";
