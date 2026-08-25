use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// URI Match Defaults policy.
pub struct UriMatchDefaultsPolicy;

impl Policy for UriMatchDefaultsPolicy {
    type Data = UriMatchDefaultsPolicyData;

    fn policy_type(&self) -> PolicyType {
        PolicyType::UriMatchDefaults
    }

    fn to_erased(&self, data: Self::Data) -> PolicyDataType {
        PolicyDataType::UriMatchDefaults(data)
    }
}

/// The URI match detection strategy used for autofill.
///
/// The integer value matches the server's wire format (and mirrors
/// `bitwarden_vault::UriMatchType`).
#[derive(Clone, Copy, Serialize_repr, Deserialize_repr, Debug, PartialEq)]
#[repr(u8)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum UriMatchType {
    /// Match by base domain.
    Domain = 0,
    /// Match by host (domain + port).
    Host = 1,
    /// Match when the detected URI starts with the saved URI.
    StartsWith = 2,
    /// Match only on an exact URI.
    Exact = 3,
    /// Match using a regular expression.
    RegularExpression = 4,
    /// Never match.
    Never = 5,
}

/// Configuration data for the URI Match Defaults policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct UriMatchDefaultsPolicyData {
    /// The default URI match detection strategy for autofill.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri_match_detection: Option<UriMatchType>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let data = UriMatchDefaultsPolicyData {
            uri_match_detection: Some(UriMatchType::Exact),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert_eq!(json, r#"{"uriMatchDetection":3}"#);
        assert_eq!(
            serde_json::from_str::<UriMatchDefaultsPolicyData>(&json).unwrap(),
            data
        );
    }

    #[test]
    fn parses_each_variant() {
        for (n, expected) in [
            (0, UriMatchType::Domain),
            (1, UriMatchType::Host),
            (2, UriMatchType::StartsWith),
            (3, UriMatchType::Exact),
            (4, UriMatchType::RegularExpression),
            (5, UriMatchType::Never),
        ] {
            let data: UriMatchDefaultsPolicyData =
                serde_json::from_str(&format!(r#"{{"uriMatchDetection":{n}}}"#)).unwrap();
            assert_eq!(data.uri_match_detection, Some(expected));
        }
    }

    #[test]
    fn empty_serializes_to_empty_object() {
        assert_eq!(
            serde_json::to_string(&UriMatchDefaultsPolicyData::default()).unwrap(),
            "{}"
        );
    }
}
