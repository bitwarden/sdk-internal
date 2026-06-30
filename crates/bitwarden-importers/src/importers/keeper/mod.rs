//! Keeper "direct" importer support.
//!
//! The Keeper direct importer logs into Keeper's API and decrypts the vault on-device. This module
//! holds the Rust port of its access layer, beginning with the cryptography ([`crypto`]). The
//! remaining access layer (vault, client, socket, keys) is still TypeScript in the `clients` repo
//! and is being migrated incrementally.
//!
//! The cryptography is currently internal Rust with **no** WASM / UniFFI bindings: the low-level
//! primitives are deliberately not exposed across the FFI boundary. Platform bindings will be added
//! once the structured access layer (records, folders, the `sync-down` protobuf) is ported, so the
//! exposed surface can be record/folder-level operations rather than raw byte arrays.

pub mod crypto;

pub use crypto::KeeperRecordKeyType;
