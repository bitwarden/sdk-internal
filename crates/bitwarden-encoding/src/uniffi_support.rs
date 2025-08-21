use crate::{b64::NotB64Encoded, b64url::NotB64UrlEncoded, B64Url, B64};

uniffi::custom_type!(B64, String, {
    try_lift: |val| {
        B64::try_from(val.as_str()).map_err(|e: NotB64Encoded| e.into())
    },
    lower: |obj| obj.to_string(),
});

uniffi::custom_type!(B64Url, String, {
    try_lift: |val| {
        B64Url::try_from(val.as_str()).map_err(|e: NotB64UrlEncoded| e.into())
    },
    lower: |obj| obj.to_string(),
});
