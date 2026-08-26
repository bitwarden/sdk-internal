use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Autotype Default Setting policy.
pub struct AutotypeDefaultSettingPolicy;

impl Policy for AutotypeDefaultSettingPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::AutotypeDefaultSetting
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::AutotypeDefaultSetting
    }
}
