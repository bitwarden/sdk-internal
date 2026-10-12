use crate::{PolicyDefinition, PolicyType, policy_type::PolicyDataType};

/// Disable Personal Vault Export policy.
pub struct DisablePersonalVaultExportPolicy;

impl PolicyDefinition for DisablePersonalVaultExportPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::DisablePersonalVaultExport
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::DisablePersonalVaultExport
    }
}
