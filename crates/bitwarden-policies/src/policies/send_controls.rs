use bitwarden_send_types::SendType;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Send Controls policy.
pub struct SendControlsPolicy;

impl Policy for SendControlsPolicy {
    type Data = SendControlsPolicyData;

    fn policy_type(&self) -> PolicyType {
        PolicyType::SendControls
    }

    fn to_erased(&self, data: Self::Data) -> PolicyDataType {
        PolicyDataType::SendControls(data)
    }
}

/// Who may access a Send.
///
/// The integer value matches the server's wire format.
#[derive(Clone, Copy, Serialize_repr, Deserialize_repr, Debug, PartialEq)]
#[repr(u8)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum SendAccessControl {
    /// Anyone with the link.
    Any = 0,
    /// Anyone with the link and the password.
    PasswordProtected = 1,
    /// Only specific people.
    SpecificPeople = 2,
}

/// Configuration data for the Send Controls policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct SendControlsPolicyData {
    /// Whether members are prevented from creating and editing Sends.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_send: Option<bool>,

    /// Who is allowed to access Sends created by members.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub who_can_access: Option<SendAccessControl>,

    /// A comma-separated list of domains recipients' emails must belong to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<String>,

    /// Whether members are prevented from hiding their email from recipients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_hide_email: Option<bool>,

    /// The Send types members are allowed to create.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_send_types: Option<Vec<SendType>>,

    /// The maximum number of hours before a Send is automatically deleted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion_hours: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_full() {
        let data = SendControlsPolicyData {
            disable_send: Some(false),
            who_can_access: Some(SendAccessControl::PasswordProtected),
            allowed_domains: Some("example.com,test.com".to_string()),
            disable_hide_email: Some(true),
            allowed_send_types: Some(vec![SendType::Text, SendType::File]),
            deletion_hours: Some(168),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains(r#""whoCanAccess":1"#));
        assert!(json.contains(r#""allowedSendTypes":[0,1]"#));
        assert_eq!(
            serde_json::from_str::<SendControlsPolicyData>(&json).unwrap(),
            data
        );
    }

    #[test]
    fn empty_serializes_to_empty_object() {
        assert_eq!(
            serde_json::to_string(&SendControlsPolicyData::default()).unwrap(),
            "{}"
        );
    }
}
