use std::str::FromStr;

use bitwarden_uniffi_error::convert_result;

use crate::{B64, B64Url};

uniffi::custom_type!(B64, String, {
    try_lift: |val| {
        convert_result(B64::from_str(&val))
    },
    lower: |obj| obj.to_string(),
});

uniffi::custom_type!(B64Url, String, {
    try_lift: |val| {
        convert_result(B64Url::from_str(&val))
    },
    lower: |obj| obj.to_string(),
});
