#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

///
/// Module containing the collection data models. It also contains the implementations for
/// Encryptable, TryFrom, and TreeItem
pub mod collection;
///
/// Module containing the error types.
pub mod error;
///
/// Module containing Tree struct that is a tree representation of all structs implementing TreeItem
/// trait. It is made using an index vector to hold the data and another vector to hold the
/// parent child relationships between those nodes.
pub mod tree;
