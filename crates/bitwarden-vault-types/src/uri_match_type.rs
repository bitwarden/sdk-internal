use serde_repr::{Deserialize_repr, Serialize_repr};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

#[allow(missing_docs)]
#[derive(Clone, Copy, Serialize_repr, Deserialize_repr, Debug, PartialEq)]
#[repr(u8)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum UriMatchType {
    Domain = 0,
    Host = 1,
    StartsWith = 2,
    Exact = 3,
    RegularExpression = 4,
    Never = 5,
}

impl TryFrom<bitwarden_api_api::models::UriMatchType> for UriMatchType {
    type Error = bitwarden_core::MissingFieldError;

    fn try_from(value: bitwarden_api_api::models::UriMatchType) -> Result<Self, Self::Error> {
        Ok(match value {
            bitwarden_api_api::models::UriMatchType::Domain => Self::Domain,
            bitwarden_api_api::models::UriMatchType::Host => Self::Host,
            bitwarden_api_api::models::UriMatchType::StartsWith => Self::StartsWith,
            bitwarden_api_api::models::UriMatchType::Exact => Self::Exact,
            bitwarden_api_api::models::UriMatchType::RegularExpression => Self::RegularExpression,
            bitwarden_api_api::models::UriMatchType::Never => Self::Never,
            bitwarden_api_api::models::UriMatchType::__Unknown(_) => {
                return Err(bitwarden_core::MissingFieldError("match"));
            }
        })
    }
}

impl From<UriMatchType> for bitwarden_api_api::models::UriMatchType {
    fn from(match_type: UriMatchType) -> Self {
        match match_type {
            UriMatchType::Domain => bitwarden_api_api::models::UriMatchType::Domain,
            UriMatchType::Host => bitwarden_api_api::models::UriMatchType::Host,
            UriMatchType::StartsWith => bitwarden_api_api::models::UriMatchType::StartsWith,
            UriMatchType::Exact => bitwarden_api_api::models::UriMatchType::Exact,
            UriMatchType::RegularExpression => {
                bitwarden_api_api::models::UriMatchType::RegularExpression
            }
            UriMatchType::Never => bitwarden_api_api::models::UriMatchType::Never,
        }
    }
}
