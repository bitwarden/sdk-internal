//! This module contains custom type converters for Uniffi.

use std::{num::NonZeroU32, str::FromStr};

use bitwarden_crypto::safe;
use bitwarden_uniffi_error::convert_result;
use uuid::Uuid;

use crate::key_management::{SignedSecurityState, V2UpgradeToken};

uniffi::use_remote_type!(bitwarden_crypto::NonZeroU32);
uniffi::use_remote_type!(bitwarden_crypto::safe::PasswordProtectedKeyEnvelope);

type DateTime = chrono::DateTime<chrono::Utc>;
uniffi::custom_type!(DateTime, std::time::SystemTime, { remote });

uniffi::custom_type!(Uuid, String, {
    remote,
    try_lift: |val| convert_result(Uuid::parse_str(&val)),
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
        convert_result(SignedSecurityState::from_str(&val))
    },
    lower: |obj| obj.into(),
});

uniffi::custom_type!(V2UpgradeToken, String, {
    try_lift: |val| convert_result(V2UpgradeToken::from_str(&val)),
    lower: |obj| obj.into(),
});
