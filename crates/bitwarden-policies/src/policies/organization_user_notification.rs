use bitwarden_organizations::OrganizationUserType;
use serde::{Deserialize, Serialize};

use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Organization User Notification policy.
pub struct OrganizationUserNotificationPolicy;

impl Policy for OrganizationUserNotificationPolicy {
    type Data = OrganizationUserNotificationPolicyData;

    fn policy_type(&self) -> PolicyType {
        PolicyType::OrganizationUserNotification
    }

    fn to_erased(&self, data: Self::Data) -> PolicyDataType {
        PolicyDataType::OrganizationUserNotification(data)
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Configuration data for the Organization User Notification policy: an
/// organization-configured banner shown to members in their vault.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct OrganizationUserNotificationPolicyData {
    /// The banner header text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,

    /// The banner description text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The label for the banner's call-to-action button.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub button_text: Option<String>,

    /// Whether the banner is shown after every login rather than once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_after_every_login: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let data = OrganizationUserNotificationPolicyData {
            header: Some("Heads up".to_string()),
            description: Some("Please rotate your credentials".to_string()),
            button_text: Some("Got it".to_string()),
            show_after_every_login: Some(false),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert_eq!(
            serde_json::from_str::<OrganizationUserNotificationPolicyData>(&json).unwrap(),
            data
        );
        assert!(json.contains("showAfterEveryLogin"));
        assert!(json.contains("buttonText"));
    }

    #[test]
    fn empty_serializes_to_empty_object() {
        assert_eq!(
            serde_json::to_string(&OrganizationUserNotificationPolicyData::default()).unwrap(),
            "{}"
        );
    }
}
