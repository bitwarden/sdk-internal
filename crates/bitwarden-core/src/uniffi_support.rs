//! This module contains custom type converters for Uniffi.

use uuid::Uuid;

type DateTime = chrono::DateTime<chrono::Utc>;
uniffi::custom_type!(DateTime, std::time::SystemTime, {
    remote,
    try_lift: |val| Ok(Self::from(val)),
    lower: |obj| obj.into(),
});

uniffi::custom_type!(Uuid, String, {
    remote,
    try_lift: |val| Uuid::parse_str(val.as_str()).map_err(|e| e.into()),
    lower: |obj| obj.to_string(),
});

// Uniffi doesn't emit unused types, this is a dummy record to ensure that the custom type
// converters are emitted
#[allow(dead_code)]
#[derive(uniffi::Record)]
struct UniffiConverterDummyRecord {
    uuid: Uuid,
    date: DateTime,
}
