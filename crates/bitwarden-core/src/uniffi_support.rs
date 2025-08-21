//! This module contains custom type converters for Uniffi.

use std::{num::NonZeroU32, str::FromStr};

use bitwarden_crypto::CryptoError;
use bitwarden_uniffi_error::convert_result;
use uuid::Uuid;

use crate::key_management::{PasswordProtectedKeyEnvelope, SignedSecurityState};

uniffi::use_remote_type!(bitwarden_crypto::NonZeroU32);

type DateTime = chrono::DateTime<chrono::Utc>;
uniffi::custom_type!(DateTime, std::time::SystemTime, { remote });

uniffi::custom_type!(Uuid, String, {
    remote,
    try_lift: |val| convert_result(Uuid::parse_str(val.as_str())),
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

uniffi::custom_type!(SignedSecurityState, String, {
    try_lift: |val| {
        convert_result(val.parse().map_err(CryptoError::EncodingError))
    },
    lower: |obj| obj.into(),
});

uniffi::custom_type!(PasswordProtectedKeyEnvelope, String, {
    remote,
    try_lift: |val| bitwarden_crypto::safe::PasswordProtectedKeyEnvelope::from_str(val.as_str())
        .map_err(|e| e.into())
        .map(PasswordProtectedKeyEnvelope),
    lower: |obj| obj.0.into(),
});
