use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Disable Personal Vault Export policy.
pub struct DisablePersonalVaultExportPolicy;

impl Policy for DisablePersonalVaultExportPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::DisablePersonalVaultExport
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::DisablePersonalVaultExport
    }
}
