//! 1Password importer.
//!
//! [`access`] is the Bitwarden-agnostic client that logs in and downloads the vaults.

// `pub` for the `test-utils` re-export. Nothing in the SDK calls into it yet.
#[allow(dead_code, unused_imports)]
pub mod access;
