//! This module contains custom type converters for Uniffi.

use std::num::NonZeroU32;

use uuid::Uuid;

uniffi::use_remote_type!(bitwarden_crypto::NonZeroU32);

type DateTime = chrono::DateTime<chrono::Utc>;
uniffi::custom_type!(DateTime, std::time::SystemTime, { remote });

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
