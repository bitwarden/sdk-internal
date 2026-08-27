//! 1Password importer.
//!
//! [`access`] is the Bitwarden-agnostic client that logs in and downloads the vaults.

// `pub` for the `test-utils` re-export. Nothing in the SDK calls into it yet.
// TODO: Make it `pub(crate)` once the importer consumes the module directly and the re-export goes.
#[allow(dead_code, unused_imports)]
pub mod access;
