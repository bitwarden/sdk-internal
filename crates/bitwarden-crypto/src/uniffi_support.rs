use std::{num::NonZeroU32, str::FromStr};

use bitwarden_sensitive_value::ExposeSensitive;
use bitwarden_uniffi_error::convert_result;

use crate::{
    CryptoError, EncString, EncodingError, PublicKey, SignedPublicKey, SymmetricCryptoKey,
    UnsignedSharedKey,
    safe::{
        DataEnvelope, HighEntropySecret, PasswordProtectedKeyEnvelope, SecretProtectedKeyEnvelope,
    },
};

uniffi::custom_type!(NonZeroU32, u32, {
    remote,
    try_lift: |val| {
        convert_result(NonZeroU32::new(val).ok_or(CryptoError::ZeroNumber))
    },
    lower: |obj| obj.get(),
});

uniffi::custom_type!(SymmetricCryptoKey, String, {
    remote,
    try_lift: |val| {
        convert_result(SymmetricCryptoKey::try_from(val.as_str().to_string()))
    },
    lower: |obj| obj.to_base64().to_string(),
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

uniffi::custom_type!(PublicKey, String, {
    try_lift: |val| {
        convert_result(PublicKey::from_str(&val)
            .map_err(|_e| EncodingError::InvalidBase64Encoding))
    },
    lower: |obj| obj.to_string(),
});

uniffi::custom_type!(DataEnvelope, String, {
    try_lift: |val| convert_result(DataEnvelope::from_str(val.as_str())),
    lower: |obj| obj.to_string(),
});

uniffi::custom_type!(PasswordProtectedKeyEnvelope, String, {
    remote,
    try_lift: |val| convert_result(PasswordProtectedKeyEnvelope::from_str(&val)),
    lower: |obj| obj.into(),
});

uniffi::custom_type!(SecretProtectedKeyEnvelope, String, {
    remote,
    try_lift: |val| convert_result(SecretProtectedKeyEnvelope::from_str(&val)),
    lower: |obj| obj.into(),
});

uniffi::custom_type!(HighEntropySecret, Vec<u8>, {
    try_lift: |val| Ok(HighEntropySecret::from_internal(&val)),
    // EXPOSE: the UniFFI lowering needs the raw bytes to cross the FFI boundary; this round-trips
    // the same secret the caller provided. The Uniffi implementation is responsible for making
    // sure the secret is not logged.
    lower: |obj| obj.as_bytes().expose_owned().to_vec(),
});
