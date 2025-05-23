use std::{num::NonZeroU32, str::FromStr};

use crate::{CryptoError, EncString, UnsignedSharedKey};

uniffi::custom_type!(NonZeroU32, u32, {
    remote,
    lower: |obj| obj.get(),
    try_lift: |val| Self::new(val).ok_or(CryptoError::ZeroNumber.into()),
});

uniffi::custom_type!(EncString, String, {
    lower: |obj| obj.to_string(),
    try_lift: |val| val.parse().map_err(|e: CryptoError| e.into()),
});

uniffi::custom_type!(UnsignedSharedKey, String, {
    lower: |obj| obj.to_string(),
    try_lift: |val| Self::from_str(&val).map_err(|e| e.into()),
});
