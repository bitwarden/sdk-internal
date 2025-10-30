use std::{num::NonZeroU32, str::FromStr};

use bitwarden_uniffi_error::convert_result;

use crate::{
    CryptoError, EncString, SignedPublicKey, UnsignedSharedKey,
    safe::{DataEnvelope, PasswordProtectedKeyEnvelope},
};

uniffi::custom_type!(NonZeroU32, u32, {
    remote,
    try_lift: |val| {
        convert_result(NonZeroU32::new(val).ok_or(CryptoError::ZeroNumber))
    },
    lower: |obj| obj.get(),
});

uniffi::custom_type!(EncString, String, {
    try_lift: |val| {
        convert_result(EncString::from_str(&val))
    },
    lower: |obj| obj.to_string(),
});

uniffi::custom_type!(UnsignedSharedKey, String, {
    try_lift: |val| {
        convert_result(UnsignedSharedKey::from_str(&val))
    },
    lower: |obj| obj.to_string(),
});

uniffi::custom_type!(SignedPublicKey, String, {
    try_lift: |val| {
        convert_result(SignedPublicKey::from_str(&val))
    },
    lower: |obj| obj.into(),
});

uniffi::custom_type!(DataEnvelope, String, {
    try_lift: |val| DataEnvelope::from_str(val.as_str())
        .map_err(|e| e.into()),
    lower: |obj| obj.to_string(),
});

uniffi::custom_type!(PasswordProtectedKeyEnvelope, String, {
    remote,
    try_lift: |val| convert_result(PasswordProtectedKeyEnvelope::from_str(&val)),
    lower: |obj| obj.into(),
});
