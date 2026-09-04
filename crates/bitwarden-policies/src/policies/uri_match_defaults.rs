use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// URI Match Defaults policy.
pub struct UriMatchDefaultsPolicy;

impl Policy for UriMatchDefaultsPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::UriMatchDefaults
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::UriMatchDefaults
    }
}
