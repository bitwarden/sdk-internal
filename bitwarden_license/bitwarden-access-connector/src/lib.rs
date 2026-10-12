//! Bitwarden PAM access connector library.
//!
//! Implements the core logic for the `bwac` binary, which continuously rotates
//! PAM-managed credentials according to configured policies and schedules.
//!
//! Only the command-line surface is present so far; the poll loop, API layer, session
//! management, and rotation pipeline land in subsequent changes.

bitwarden_commercial_marker::commercial_crate!();

/// CLI argument definitions (exposed for `main.rs`).
pub mod cli;
