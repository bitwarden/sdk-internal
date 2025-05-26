use std::{num::NonZeroU32, str::FromStr};

use crate::{CryptoError, EncString, UnsignedSharedKey};

uniffi::custom_type!(NonZeroU32, u32, {
    remote,
    try_lift: |val| {
        NonZeroU32::new(val).ok_or(CryptoError::ZeroNumber.into())
    },
    lower: |obj| obj.get(),
});

uniffi::custom_type!(EncString, String, {
    try_lift: |val| {
        EncString::from_str(&val).map_err(|e: CryptoError| e.into())
    },
    lower: |obj| obj.to_string(),
});

uniffi::custom_type!(UnsignedSharedKey, String, {
    try_lift: |val| {
        UnsignedSharedKey::from_str(&val).map_err(|e: CryptoError| e.into())
    },
    lower: |obj| obj.to_string(),
});
