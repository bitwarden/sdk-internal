//! Keeper protobuf message types.
//!
//! Generated from proto definitions in `proto/keeper/`. Exposes all Keeper API and data structure
//! messages used by the direct importer: login requests/responses, vault sync, records, folders,
//! and push notifications.
//!
//! Generated modules are named after their proto package names, not file names.

#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(clippy::enum_variant_names)]

// Generated protobuf modules (regenerate with support/build-keeper-proto.sh)
pub mod authentication;
pub mod breach_watch;
pub mod enterprise;
pub mod graph_sync;
pub mod notification_center;
pub mod push;
pub mod records;
pub mod sso_cloud;
pub mod tokens;
pub mod vault;

#[cfg(test)]
mod tests;
