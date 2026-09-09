use bitwarden_organizations::OrganizationUserType;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Maximum Vault Timeout policy.
pub struct MaximumVaultTimeoutPolicy;

impl Policy for MaximumVaultTimeoutPolicy {
    type Data = MaximumVaultTimeoutPolicyData;

    fn policy_type(&self) -> PolicyType {
        PolicyType::MaximumVaultTimeout
    }

    fn to_erased(&self, data: Self::Data) -> PolicyDataType {
        PolicyDataType::MaximumVaultTimeout(data)
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[OrganizationUserType::Owner]
    }
}

/// The kind of vault timeout the policy enforces.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum VaultTimeoutType {
    /// The vault never times out.
    Never,
    /// The vault times out when the app restarts.
    OnAppRestart,
    /// The vault times out when the system locks.
    OnSystemLock,
    /// The vault times out immediately.
    Immediately,
    /// The vault times out after a custom duration (see
    /// [`MaximumVaultTimeoutPolicyData::minutes`]).
    Custom,
}

/// The action taken when the vault times out.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum VaultTimeoutAction {
    /// Lock the vault, requiring the member to unlock it again.
    Lock,
    /// Log the member out entirely.
    LogOut,
}

/// Configuration data for the Maximum Vault Timeout policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct MaximumVaultTimeoutPolicyData {
    /// The kind of vault timeout enforced. Serialized as `type` on the wire.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub timeout_type: Option<VaultTimeoutType>,

    /// The maximum allowed vault timeout, in minutes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minutes: Option<i32>,

    /// The action taken when the vault times out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<VaultTimeoutAction>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let data = MaximumVaultTimeoutPolicyData {
            timeout_type: Some(VaultTimeoutType::Custom),
            minutes: Some(480),
            action: Some(VaultTimeoutAction::LogOut),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains(r#""type":"custom""#));
        assert!(json.contains(r#""action":"logOut""#));
        assert!(json.contains(r#""minutes":480"#));
        assert_eq!(
            serde_json::from_str::<MaximumVaultTimeoutPolicyData>(&json).unwrap(),
            data
        );
    }

    #[test]
    fn parses_string_union_values() {
        let data: MaximumVaultTimeoutPolicyData =
            serde_json::from_str(r#"{"type":"onAppRestart","action":"lock"}"#).unwrap();
        assert_eq!(data.timeout_type, Some(VaultTimeoutType::OnAppRestart));
        assert_eq!(data.action, Some(VaultTimeoutAction::Lock));
    }

    #[test]
    fn empty_serializes_to_empty_object() {
        assert_eq!(
            serde_json::to_string(&MaximumVaultTimeoutPolicyData::default()).unwrap(),
            "{}"
        );
    }
}
