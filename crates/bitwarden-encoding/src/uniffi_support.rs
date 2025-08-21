use crate::{b64::NotB64Encoded, b64url::NotB64UrlEncoded, B64Url, B64};

uniffi::custom_type!(B64, String, {
    try_lift: |val| {
        val.parse().map_err(|e: NotB64Encoded| e.into())
    },
    lower: |obj| obj.to_string(),
});

uniffi::custom_type!(B64Url, String, {
    try_lift: |val| {
        val.parse().map_err(|e: NotB64UrlEncoded| e.into())
    },
    lower: |obj| obj.to_string(),
});
