//! Emits entries onto **custom tracks in the Chrome DevTools performance panel**, using the
//! [performance extensibility API][extensibility]: a `performance.measure()` whose
//! `detail.devtools` carries `dataType: "track-entry"` is drawn as its own timeline lane rather
//! than under _User Timing_.
//!
//! Everything here is a no-op on non-`wasm32` targets, so call sites need no `cfg`.
//!
//! ```text
//!   ── Shared Unlock ───────────────────────────────  ◀ track group
//!       Announces   ▏▏     ▏▏▏        ▏▏              ◀ track
//!       Biometrics        ▉▉▉▉▉▉
//!   ── IPC ────────────────────────────────────────
//!       Messages    ▏▏▏▏   ▏▏  ▏▏▏▏   ▏▏
//!       Noise       ▉▉▉
//! ```
//!
//! An entry either spans an operation, by holding the guard [`TrackEntry::timed`] returns for the
//! duration of the work, or collapses to a zero-length tick via [`TrackEntry::emit`]. Properties
//! show up in the DevTools details pane when the entry is selected; those known only once the work
//! has run go on the guard.
//!
//! ```
//! use bitwarden_logging::devtools_trace::TrackEntry;
//!
//! fn handshake() -> Result<Vec<u8>, ()> {
//!     let mut timed = TrackEntry::new("IPC", "Noise", "Handshake")
//!         .prop("destination", "DesktopMain")
//!         .timed();
//!
//!     let session = Err(())?; // The entry is drawn even here, spanning up to the `?`.
//!
//!     timed.prop("outcome", "established");
//!     Ok(session)
//! }
//! ```
//!
//! Unlike the flight recorder, this is a live debugging aid rather than telemetry: nothing is
//! buffered, persisted or exported, and it is only visible to whoever has DevTools open. Never
//! pass key material or vault data as a property — the values are rendered verbatim in the UI and
//! captured in exported traces.
//!
//! [extensibility]: https://developer.chrome.com/docs/devtools/performance/extension

mod entry;
pub use entry::{TimedGuard, TrackEntry};

#[cfg(target_arch = "wasm32")]
mod wasm;
