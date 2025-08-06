use std::{num::NonZeroU32, str::FromStr};

use bitwarden_uniffi_error::convert_result;

use crate::{CryptoError, EncString, SignedPublicKey, UnsignedSharedKey};

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
        convert_result(val.parse().map_err(CryptoError::EncodingError))
    },
    lower: |obj| obj.into(),
});
