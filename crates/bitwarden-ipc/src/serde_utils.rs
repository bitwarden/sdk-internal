//! Global serialization and deserialization utilities for IPC messages.
//! This module provides functions to serialize and deserialize IPC messages in one place,
//! ensuring consistency and reducing code duplication across the IPC crate.

use serde::{de::DeserializeOwned, Serialize};

pub(crate) type SerializeError = serde_json::Error;
pub(crate) type DeserializeError = serde_json::Error;

pub(crate) fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(value)
}

pub(crate) fn from_slice<T: DeserializeOwned>(data: &[u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice(data)
}
