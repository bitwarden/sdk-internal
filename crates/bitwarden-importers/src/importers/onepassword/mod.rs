//! 1Password importer.
//!
//! [`access`] is the Bitwarden-agnostic client that logs in and downloads the vaults.
//! [`convert`] maps what it returns onto the importer's parsed shape.

// Both are `pub` for the `test-utils` re-export. Nothing in the SDK calls into them yet.
// TODO: Make them `pub(crate)` and drop the allows once the importer consumes the modules directly
// and the re-export goes.
#[allow(dead_code, unused_imports)]
pub mod access;
#[allow(dead_code)]
pub mod convert;
