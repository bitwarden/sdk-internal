use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Single Organization policy.
pub struct SingleOrgPolicy;

impl Policy for SingleOrgPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::SingleOrg
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::SingleOrg
    }
}
