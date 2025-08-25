//! This module contains custom type converters for Uniffi.

use std::{num::NonZeroU32, str::FromStr};

use serde_json::Value;
use uuid::Uuid;

uniffi::custom_type!(Uuid, String, {
    remote,
    try_lift: |val| Uuid::parse_str(val.as_str()).map_err(|e| e.into()),
    lower: |obj| obj.to_string(),
});

uniffi::custom_type!(Value, String, {
    remote,
    try_lift: |val| Value::from_str(&val).map_err(|e| e.into()),
    lower: |obj| obj.to_string(),
});

// Uniffi doesn't emit unused types, this is a dummy record to ensure that the custom type
// converters are emitted
#[allow(dead_code)]
#[derive(uniffi::Record)]
struct UniffiConverterDummyRecord {
    uuid: Uuid,
}
